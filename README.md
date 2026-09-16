# Placitum cookie

English · [Русский](README.ru.md)

Placitum cookie inspector. It issues a signed cookie to the client, drops it, writes its value to a
live set and tells the neighbours about it. It checks nothing and blocks nobody: other parts decide
by the issued cookie, such as the local layer on the node, neighbour actions or the counter.

Ad traffic shows it best. A client arrives by a link with `utm_source=yandex-direct`; the inspector
gives them a signed cookie labelled with the source, writes the value to a live set and marks the
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
      default: direct        # label when there is no source
      random: 8              # random tail in bytes; 0 means none
      max_len: 64            # label limit before the value is built

conditions:              # named conditions, the same as in the action inspector
  - name: from_ads
    any:
      - { value: $arg_utm_source, op: eq, text: yandex-direct }
      - { value: $arg_utm_source, op: eq, text: google }

rules:
  - name: first-touch    # the name lives in the log and the audit
    phase: request       # request | response; empty means both
    on: absent           # cookie state on arrival; empty means any
    if: from_ads         # a profile condition; unless inverts it
    match:
      methods: [GET]
    issue: waf_src       # operation: issue
    actions:
      - do: mark
        marker: "src:{tag}"   # substitutions: {tag}, {value}, {name}
      - list: ads_clients     # write to a live set
        write: cookie         # addr | net | net_all | asn | cookie
        ttl: 30d
        code: COOKIE_ADS

  - name: forged         # the signature does not match: someone made the cookie up
    on: invalid
    cookie: waf_src
    actions:
      - { do: score, value: 20, code: COOKIE_FORGED }

  - name: from-google    # the label of the presented cookie is one of these
    cookie: waf_src
    tags: [google]
    actions:
      - { do: mark, marker: "src:{tag}" }

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

`tags: [google, yandex]` narrows a rule to the readable half of the value: it fires when the label
of the presented cookie is one of those named. Only a cookie that exists has a label (`present`,
`expired`), so such a rule does not load with `on: absent` or `on: invalid`. The client chooses the
label of an unsigned cookie, so decide by labels only with `sign: hmac`.

Rules accumulate: every matching rule fires, and actions add up in row order. The cookie itself is
not decided by order: **dropping beats issuing**, so a logout rule never loses to a landing-page rule
placed below it.

### Value and signature

```
<label>[~<random>][.<time>.<signature>]
```

The label is why the cookie exists: the traffic source, the campaign, the test branch. It is
readable and goes into the record marker, so its alphabet is narrow: anything outside
`[A-Za-z0-9_-]` becomes an underscore, and the label is cut at `max_len`.

The key comes from `WAF_COOKIE_SECRET_FILE` or `WAF_COOKIE_SECRET`, at least 16 bytes, the same for
every copy. It is derived per cookie name, so the signature of one cookie does not fit another.
Without a key a profile with `sign: hmac` answers `error` with `COOKIE_SECRET_MISSING` instead of
quietly issuing unsigned cookies. The issue time lives in the signed half, so `renew_after` and the
`expired` state need `sign: hmac`.

### Writes to live sets

An action can be a write instead of a request: `list` with `ttl` (and `write`, `op`, `code`), without
`to` and `do`. `write` has the four kinds shared by every sender and one of its own:

| `write` | What goes to the set |
| --- | --- |
| `addr` | the client address (default) |
| `net` | the effective announcement, the narrowest |
| `net_all` | every announcement covering the address, including wider ones |
| `asn` | the whole autonomous system |
| `cookie` | the cookie value: issued on this request or presented by the client |

`write: cookie` is what the set of a node is usually built for: a `type=string` set, almost always
with `hash=md5` so that cookie values do not sit in shared memory in clear text. `op: remove` deletes
the record. Announcements and systems come from the geo coder (`WAF_COOKIE_GEO_ADDR`) within the
message budget; a silent coder means `error` with `COOKIE_GEO_UNAVAILABLE`.

## Reason codes

| Code | Meaning |
| --- | --- |
| `COOKIE_OK` | the rules were evaluated |
| `COOKIE_IDLE` | not its phase (WebSocket frames) |
| `COOKIE_PROFILE_OFF` | the profile has `mode: off` |
| `COOKIE_UNKNOWN_PROFILE` | the route names a profile the inspector does not have |
| `COOKIE_HEADERS_UNAVAILABLE` | the route does not capture request headers |
| `COOKIE_STORE_ERROR` | the exchange did not return an object that was there |
| `COOKIE_SECRET_MISSING` | the cookie is signed, but the process has no key |
| `COOKIE_ISSUE_FAILED` | the value could not be built: too long, no random bytes |
| `COOKIE_GEO_UNAVAILABLE` | a row writes a network or a system, and the coder is silent |
| `COOKIE_QUEUE_LIMIT`, `COOKIE_DEADLINE_EXCEEDED` | overload: the queue is full or the budget is gone |

What it needs and all settings are in [INSTALL.md](INSTALL.md).

## License

[Placitum License Agreement](LICENSE.md). A Russian translation is in [LICENSE.ru.md](LICENSE.ru.md);
the English text is the legally binding one.
