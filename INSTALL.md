# Installation

English · [Русский](INSTALL.ru.md)

The inspector does not listen on the network: it is a subscriber of the `waf.req.cookie` queue on the
bus. It needs no address and no service, and adding a copy touches neither the protection node nor
the configuration. Usually `placitum-core` installs it.

## What it needs

| Component | Required | Why |
| --- | --- | --- |
| NATS | yes | the queue, audit, log, profile generations |
| Signing key | if cookies are signed | HMAC of the value; without a key a profile with `sign: hmac` answers `error` |
| Exchange Redis | yes | request headers: without `Cookie` there is nothing to read |
| Internal Redis | for set writes | the mirror of keeper sets; without it the exchange is used |
| `keeper` | for set writes | keeps the content of live sets |
| `geo` | for `write: net`, `net_all`, `asn` | announcements and system composition |
| Controller | yes | sends profiles as generations |

## Signing key

At least 16 bytes and **the same for every copy**: a cookie issued by one copy must be readable by
another.

```sh
openssl rand -hex 32 > secrets/cookie.hmac
```

Pass the key as a file (`WAF_COOKIE_SECRET_FILE`), not as a variable: the environment of a process
is visible to its neighbours on the machine and ends up in dumps. The file wins when both are set.

**Changing the key makes every issued cookie forged.** Each cookie signed with the old key arrives
as `invalid`, and if the profile scores `invalid`, every returning client gets those points at once.
Change the key together with the profile, not alone.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | bus |
| `REDIS_URL` | from `inspector.conf` | exchange: request headers and query string |
| `REDIS_INTERNAL_URL` | from `inspector.conf` | internal Redis: the mirror of keeper sets |
| `WAF_COOKIE_SUBJECT` | `waf.req.cookie` | subscription; must match `subject=` in the inspector declaration |
| `WAF_COOKIE_NAME` | `cookie` | name in the inspector registry and the presence frame |
| `WAF_COOKIE_QUEUE` | the name | queue group on the bus |
| `WAF_COOKIE_PROFILES` | `./profiles`; `/app/profiles` in the image | profiles; controller generations override them |
| `WAF_COOKIE_DATA` | `<profiles>.applied`; `/var/lib/waf/cookie` in the image | where rollout puts the applied generation |
| `WAF_COOKIE_RELOAD_EVERY` | `1s` | how often to check the profile directory |
| `WAF_COOKIE_SECRET_FILE` | empty | file with the signing key |
| `WAF_COOKIE_SECRET` | empty | the key as a variable, when there is no file |
| `WAF_COOKIE_GEO_ADDR` | empty | geo coder (`host:port`) for network and system writes |
| `WAF_COOKIE_GEO_TIMEOUT`, `WAF_COOKIE_GEO_NEG_MAX` | `500ms`, `0` | coder wait within the message budget and negative cache limit |
| `WAF_COOKIE_CONF` | `inspector.conf` in the working directory, then `/app/inspector.conf` | queue and Redis settings |
| `WAF_COOKIE_WORKERS` | number of CPUs | workers |
| `WAF_COOKIE_QUEUE_DEPTH`, `WAF_COOKIE_QUEUE_FULL`, `WAF_COOKIE_QUEUE_EXPAND` | `256`, `drop`, `off` | queue and overflow behaviour; the same through `inspector.conf` |
| `WAF_COOKIE_RESERVE_MS`, `WAF_COOKIE_MIN_BUDGET_MS` | `1`, `1` | reserve for the answer and the minimum budget below which work does not start |
| `WAF_COOKIE_VERSIONS` | `2` | accepted message schema versions |
| `WAF_COOKIE_LOG` | `info` | starting log level; the panel changes it live |
| `WAF_HEARTBEAT_EVERY` | `4s` | presence frame interval |
| `WAF_LOG_SHIP` | `on` | whether the process log goes to the bus; `off` keeps it on stdout only |

## Docker Compose

```yaml
services:
  inspector-cookie:
    image: placitum/cookie
    environment:
      NATS_URL: nats://nats:4222
      REDIS_URL: redis://redis:6379
      REDIS_INTERNAL_URL: redis://redis-internal:6379
      WAF_COOKIE_SECRET_FILE: /run/secrets/waf_cookie_hmac
      WAF_COOKIE_GEO_ADDR: geo:50051
    secrets: [waf_cookie_hmac]
    depends_on: [nats, redis, redis-internal]

secrets:
  waf_cookie_hmac:
    file: ./secrets/cookie.hmac
```

## Checking

The image has a probe that sends a real message over the bus; the `HEALTHCHECK` runs it:

```sh
docker exec <container> cookie-probe --quiet --timeout 1s
```

On a route with an issuing profile the response must carry `Set-Cookie`:

```sh
curl -si 'http://<node>/?utm_source=test' | grep -i '^set-cookie'
```

A healthy start logs the bus connection, the loaded profiles and the worker count. If `Set-Cookie`
does not come, first look at the call mode on the route: a passive inspector issues no cookies.

## Pitfalls

- **A passive call issues nothing.** With `mode=passive` or `mode=vote` on the call the module does
  not apply the `cookies` section of the answer. It looks like "turned on, but no cookie".
- **Two phases, two issues.** A call in both phases of a route runs twice; the issuing rule then
  needs `phase:`.
- **Host-only.** The module never sets `Domain`: a cookie of `shop.example.com` is not visible on
  `www.example.com`.
- **Cache.** `Set-Cookie` on a cached response lets one client carry away another's cookie. Keep
  static content out of issuing rules.
- **Length.** A `type=string` set holds records up to 256 bytes, 32 with `hash=md5`; a signed value
  counts whole.
