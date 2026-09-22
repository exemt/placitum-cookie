# Placitum cookie

English · [Русский](README.ru.md)

Placitum cookie inspector. It issues a signed cookie to the client, drops it, writes its value to a
live set and tells the neighbours about it. It checks nothing and blocks nobody: other parts decide
by the issued cookie, such as the local layer on the node, neighbour actions or the counter.

Ad traffic shows it best. A client arrives by a link with `utm_source=yandex-direct`; the inspector
gives them a signed cookie whose value is the source, writes the cookie to a live set and marks the
record `src:yandex-direct`. The campaign shows up in the log without a single trip to the
application, and the node recognises the client by the set without the bus or the inspector.

```
module ──► waf.req.cookie ──► cookie ──► allow + Set-Cookie
                                 │
                                 ├── cookie state: absent | present | invalid | expired
                                 ├── the value written to a live set
                                 └── requests to neighbours: marker, score
```

## What to know

- **Its only verdict is `allow`.** It moves the route score with a `score` request that the module
  carries out. Its own failures are `verdict: error` with a `COOKIE_*` code, not a quiet `allow`:
  an `allow` would hide a cookie that was never issued.
- **It works in both phases.** In the request phase the cookie is set before the upstream and the
  application sees it too. In the response phase the status is known, so a client who got 404 need
  not get a cookie. Request headers in the response phase come from the request snapshot: `Cookie`
  is sent by the client, not by the upstream.
- **Signed by default.** A cookie that the installation acts upon can be typed by hand in a browser
  console if it is not signed. A forged value is the `invalid` state, not "no cookie".
- **The route must capture headers.** Without them there is nothing to read the cookie from, and
  the answer is `error` with `COOKIE_HEADERS_UNAVAILABLE`. Treating that as "no cookie" would give
  every client a new cookie on every request.

## Route

```nginx
waf_inspector cookie subject=waf.req.cookie;

location / {
    waf_inspect request cookie wave=1 timeout=20ms;
    waf_capture request headers args;
    waf_cookie_defaults secure=on http_only=on same_site=Lax;
}
```

`args` is needed when the value comes from the query string (`value.from: $arg_utm_source`). The
`secure`, `http_only` and `same_site` attributes come from `waf_cookie_defaults` of the route, not
from the profile: the module parses and discards what arrives over the wire. The module never sets
`Domain`, so the cookie stays host-only.

## Profile

Profiles come from the controller as a generation; the image holds an empty `default`. A route that
names a profile the inspector does not have gets `error` with `COOKIE_UNKNOWN_PROFILE`.

```yaml
mode: enforce

cookies:                 # declarations: what the cookie is
  - name: waf_src
    path: /              # default /
    max_age: 30d         # none means a session cookie
    renew_after: 7d      # age after which the state is expired
    sign: hmac           # hmac (default) | none
    value:
      from: $arg_utm_source  # operand: $arg_, $http_, $cookie_, $waf_request_args.<name>
      default: direct        # the value when the request has none; alone it is a constant
      random: 0              # a unique number in bytes (default 8); alone it is the value (uid)
      max_len: 64            # value limit; longer is cut
  - name: uid
    max_age: 365d
    value: { random: 8 }     # a number of its own for every client: 16 hex digits

rules:
  - name: first-touch    # the name lives in the log and the audit
    phase: request       # request | response; empty means both
    on: absent           # cookie state on arrival; empty means any
    match:               # every given field must match; empty means any request
      path_prefix: /catalog
      methods: [GET]
    issue: waf_src       # operation: issue
    actions:
      - do: mark
        marker: "src:{value}" # substitutions: {value}, {cookie} (the whole string), {name}
      - list: ads_clients     # write to a live set
        write: cookie         # value | cookie | addr | net | net_all | asn
        ttl: 30d
        code: COOKIE_ADS

  - name: forged         # the signature does not match: someone made the cookie up
    on: invalid
    cookie: waf_src
    actions:
      - { do: score, value: 20, code: COOKIE_FORGED }

  - name: from-google    # the value of the presented cookie is one of these
    cookie: waf_src
    tags: [google]         # not_tags: none of these
    actions:
      - { do: mark, marker: "src:{value}" }

  - name: partner        # the value is in a static list: it comes with the generation
    on: present
    cookie: waf_src
    listed: { list: partners, op: in, static: true }
    actions:
      - { do: mark, marker: "partner:{value}" }

  - name: sign-out       # the number of the client goes to a dynamic list...
    on: present
    cookie: uid
    match: { path_prefix: "/logout" }
    actions:
      - { list: revoked, write: value, ttl: 30d }

  - name: revoked        # ...and a cookie with that number is dropped when it comes back
    on: present
    cookie: uid
    listed: { list: revoked, op: in }   # op: in | not_in; hash: md5 for a hashed list
    drop: uid

  - name: logout
    match: { path_prefix: "/logout" }
    drop: waf_src        # operation: drop
    actions:
      - { list: ads_clients, write: cookie, op: remove }
```

### States and operations

| `on` | When |
| --- | --- |
| `absent` | the client sent no cookie with this name |
| `present` | the cookie is there and the signature matches, or no signature was asked for |
| `invalid` | the cookie is there, but the signature does not match, the form is broken or the issue time is in the future |
| `expired` | the cookie is ours and intact, but older than `renew_after` |

There are two operations, `issue` and `drop`, and a rule does one of them. `on: absent` with `issue`
is first touch: only a client without the cookie gets it. A rule without `on:` is last touch: the
value is rewritten on every matching request.

`tags: [google, yandex]` narrows a rule by the value: it fires when the value of the presented cookie
is one of those named (`not_tags`: none of them). Only a cookie that exists has a value (`present`,
`expired`), so such a rule does not load with `on: absent` or `on: invalid`. The client chooses the
value of an unsigned cookie, so decide by values only with `sign: hmac`.

`listed` looks the value of the cookie up in a list: the value, the same one a `write: value` puts
there. A dynamic list is mirrored over the keeper protocol from the internal Redis. A static list
(`static: true`) is only compared with and comes with the generation: the manifest names it with the
sha256 of its body, the inspector reads the body from the internal Redis (`waf.blob.<hex>`), checks the
hash and keeps it next to the profiles (`profiles/.lists/<name>.txt`, one value per line). A profile
whose static list is not there does not load. With `hash: md5` the value is hashed before the lookup.
No value, or a dynamic list the mirror has not received yet, make `in` false and `not_in` true:
missing data never turns into a match, and the `kind=inspector` event notes such a list under `notes`.

A rule is narrowed only by what it holds itself: `on`, `tags` or `not_tags`, `listed`, `phase`,
`status` (response codes, with `phase: response`) and `match` (`path_prefix`, `methods`, `suffixes`,
`static`). A cookie profile has no conditions: a profile with `conditions`, `if` or `unless` does not
load, because dropping them quietly would widen the rules.

Rules accumulate: every matching rule fires, and actions add up in row order. The cookie itself is
not decided by order: **dropping beats issuing**, so a logout rule never loses to a landing-page rule
placed below it.

### Value and signature

```
<value>[.<time>.<signature>]
<value>~<random>[.<time>.<signature>]   a value with a number, as a hand-written profile may ask
```

The value is why the cookie exists: the client, the traffic source, the campaign. It is one of three:
`value.random` alone, a unique number (uid) of its own for every client; `value.default` alone, a
constant; or `value.from`, a request variable, with `value.default` as the fallback when the request
has none. A client whose request has neither gets no cookie, and the `kind=inspector` event names such
a cookie under `no_value`. Rules compare the value (`tags`, `listed`), markers get it as `{value}`, and
`write: value` puts it into a list. Its alphabet is narrow: anything outside `[A-Za-z0-9_-]` becomes an
underscore, and the value is cut at `max_len`. With both a value and a number the value is the part
before `~`. The whole string, with the time and the signature, is the `{cookie}` of a marker and what
`write: cookie` puts into a list.

The key comes from `WAF_COOKIE_SECRET_FILE` or `WAF_COOKIE_SECRET`, at least 16 bytes, the same for
every copy. It is derived per cookie name, so the signature of one cookie does not fit another.
Without a key a profile with `sign: hmac` answers `error` with `COOKIE_SECRET_MISSING` instead of
quietly issuing unsigned cookies. The issue time lives in the signed half, so `renew_after` and the
`expired` state need `sign: hmac`.

### Writes to live sets

An action can be a write instead of a request: `list` with `ttl` (and `write`, `op`, `cookie`, `code`),
without `to` and `do`. Only a dynamic list is written. `write` has the four kinds shared by every
sender and two of its own:

| `write` | What goes to the set |
| --- | --- |
| `addr` | the client address (default) |
| `net` | the effective announcement, the narrowest |
| `net_all` | every announcement covering the address, including wider ones |
| `asn` | the whole autonomous system |
| `value` | the value of the cookie, the one `listed` compares |
| `cookie` | the whole cookie string: value, time and signature, issued on this request or presented by the client |

`cookie:` names the cookie of both; without it the write takes the rule's cookie, and an overload rule,
which has none, names it. `write: value` feeds the lists the rules of this inspector check. `write:
cookie` is what the set of a node is usually built for: a `type=string` set, almost always with
`hash=md5` so that cookie values do not sit in shared memory in clear text. `op: remove` deletes the
record. Announcements and systems come from the network directory (`WAF_COOKIE_GEO_ADDR`) within the
message budget; a silent network directory means `error` with `COOKIE_GEO_UNAVAILABLE`.

## Reason codes

| Code | Meaning |
| --- | --- |
| `COOKIE_OK` | the rules were evaluated |
| `COOKIE_IDLE` | not its phase (WebSocket frames) |
| `COOKIE_PROFILE_OFF` | the profile has `mode: off` |
| `COOKIE_UNKNOWN_PROFILE` | the route names a profile the inspector does not have |
| `COOKIE_HEADERS_UNAVAILABLE` | the route does not capture request headers |
| `COOKIE_STORE_ERROR` | the buffer did not return an object that was there |
| `COOKIE_SECRET_MISSING` | the cookie is signed, but the process has no key |
| `COOKIE_ISSUE_FAILED` | the value could not be built: too long, no random bytes |
| `COOKIE_GEO_UNAVAILABLE` | a row writes a network or a system, and the network directory is silent |
| `COOKIE_QUEUE_LIMIT`, `COOKIE_DEADLINE_EXCEEDED` | overload: the queue is full or the budget is gone |

What it needs and all settings are in [INSTALL.md](INSTALL.md).

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
