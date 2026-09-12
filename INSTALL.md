# Установка

Инспектор не слушает сеть: он подписчик очереди `waf.req.cookie` на шине. Ни адреса, ни Service
ему не нужно, и добавление копии не трогает ни узел защиты, ни конфигурацию. Обычно его
поднимает фундамент установки (`placitum-core`).

## Что нужно рядом

| Компонент | Обязателен | Зачем |
| --- | --- | --- |
| NATS | да | очередь, аудит, журнал, поколение профилей |
| Ключ подписи | да, если кука подписывается | HMAC значения; без ключа профиль с `sign: hmac` отвечает отказом |
| Redis: обменник | да | заголовки запроса: без `Cookie` читать не по чему |
| Redis: внутренний | при записи в наборы | зеркало составов keeper |
| `keeper` | при записи в наборы | ведёт состав живых наборов |
| `geo` | при `write: net \| net_all \| asn` | анонсы и состав системы |
| Контроллер | да | шлёт профили поколением |

## Что нужно от маршрута

Инспектор читает куку из снимка заголовков, поэтому маршрут обязан их снимать:

```nginx
waf_inspector cookie subject=waf.req.cookie;

location / {
    waf_inspect cookie wave=1 timeout=20ms;
    waf_capture request headers args;
    waf_cookie_defaults secure=on http_only=on same_site=Lax;
}
```

Без `waf_capture request headers` ответ — `error` с `COOKIE_HEADERS_UNAVAILABLE`. Молча считать
«куки нет» было бы хуже: новая кука каждому клиенту на каждом запросе.

## Ключ подписи

Не короче 16 байт, **один на все копии**: кука, выданная одной копией, должна читаться другой.

```sh
openssl rand -hex 32 > secrets/cookie.hmac
```

Ключ отдаётся файлом (`WAF_COOKIE_SECRET_FILE`), а не переменной: окружение процесса видно
соседям по машине и уезжает в дампы. Файл сильнее переменной, если заданы оба.

**Смена ключа делает все выданные куки поддельными.** Каждая кука, подписанная прежним ключом,
придёт в состоянии `invalid` — и если в профиле на `invalid` навешены очки, их получат все
вернувшиеся клиенты разом. Меняйте ключ вместе с профилем, а не в одиночку.

## Переменные

| Переменная | По умолчанию | Что |
| --- | --- | --- |
| `NATS_URL` | `nats://127.0.0.1:4222` | шина |
| `REDIS_URL` | из `inspector.conf` | обменник: заголовки и строка запроса |
| `REDIS_INTERNAL_URL` | из `inspector.conf` | внутренний Redis: зеркало наборов |
| `WAF_COOKIE_SUBJECT` | `waf.req.cookie` | подписка |
| `WAF_COOKIE_NAME` | `cookie` | имя в реестре инспекторов и в кадре присутствия |
| `WAF_COOKIE_PROFILES` | `./profiles` | каталог профилей из образа |
| `WAF_COOKIE_DATA` | `<профили>.applied` | куда раскатка кладёт применённое поколение |
| `WAF_COOKIE_SECRET_FILE` | — | файл с ключом подписи |
| `WAF_COOKIE_SECRET` | — | ключ переменной, если файла нет |
| `WAF_COOKIE_GEO_ADDR` | — | кодер гео (`host:port`) для записей подсети и системы |
| `WAF_COOKIE_GEO_TIMEOUT`, `WAF_COOKIE_GEO_NEG_MAX` | | ожидание кодера в бюджете сообщения и потолок отрицательного кэша |
| `WAF_COOKIE_LOG` | `info` | стартовый уровень журнала; живьём его переставляет панель |
| `WAF_COOKIE_VERSIONS` | `2` | версии схемы сообщения, которые процесс принимает |
| `WAF_COOKIE_WORKERS`, `WAF_COOKIE_QUEUE_DEPTH`, `WAF_COOKIE_QUEUE_FULL`, `WAF_COOKIE_CONF` | | очередь и её поведение; то же через `inspector.conf` |

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

## Проверка после запуска

Своего порта и пробы у инспектора нет, поэтому проверяют его по шине и по трафику.

```sh
# Кадр присутствия: копия подписана на очередь и готова
nats sub 'WAF_STATUS.inspector.cookie.>' --count 1

# Маршрут с профилем выдачи: в ответе должен прийти Set-Cookie
curl -si 'http://узел/?utm_source=test' | grep -i '^set-cookie'
```

В журнале при здоровом старте: подключение к шине, загруженные профили, число воркеров. Если
`Set-Cookie` не приходит — первым делом смотрите режим вызова на маршруте: пассивный инспектор
куки не выдаёт.

## Грабли

- **Пассивный не выдаёт.** `mode=passive` и `mode=vote` на вызове: модуль секцию `cookies` от
  такого ответа не применяет. Выглядит как «включил, а куки нет».
- **Две фазы — две выдачи.** Вызов на обеих фазах маршрута отработает дважды; у правила выдачи
  тогда обязателен `phase:`.
- **Host-only.** `Domain` модуль не ставит: кука с `shop.example.com` не видна на
  `www.example.com`.
- **Кеш.** `Set-Cookie` на кешируемом ответе — один клиент уносит куку другого. Статику из правил
  выдачи исключайте.
- **Длина.** Набор `type=string` держит запись до 256 байт, с `hash=md5` — 32; подписанное
  значение считается целиком.
