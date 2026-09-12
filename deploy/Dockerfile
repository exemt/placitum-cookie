# Контекст сборки -- корень инспектора. Отсюда же сборка прямо из git:
#
#     docker build -f deploy/Dockerfile -t placitum/cookie .
#     docker buildx build -f deploy/Dockerfile -t placitum/cookie \
#         "https://github.com/exemt/placitum-cookie.git#develop"

FROM golang:1.25-alpine AS build

WORKDIR /src

# Прокси модулей -- аргументом: в изолированном контуре подставляют своё зеркало.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0

# Зависимости отдельным слоем; download, а не tidy: сборка обязана повторять
# go.mod, а не переписывать его.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# Тесты в сборке: подпись куки -- то, на чём контур принимает решения, и образ
# с красными тестами подписи ставить нельзя тем более.
RUN go test ./...

# Сборка в бинарь: версия и ревизия видны в журнале старта и в кадре
# присутствия, а не только в метках образа.
ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/cookie ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/cookie-probe ./cmd/probe

FROM alpine:3.22

# Версия и ревизия приходят снаружи: .git в контекст сборки не попадает.
ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/cookie" \
      org.opencontainers.image.description="Placitum cookie inspector: issues and drops signed cookies, writes their values to live lists" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-cookie" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/cookie /out/cookie-probe /usr/local/bin/
COPY profiles ./profiles
COPY inspector.conf ./inspector.conf

RUN adduser -D -H -u 10001 cookie && \
    mkdir -p /var/lib/waf/cookie && \
    chown -R cookie:cookie /app /var/lib/waf
USER cookie

ENV NATS_URL=nats://nats:4222 \
    WAF_COOKIE_SUBJECT=waf.req.cookie \
    WAF_COOKIE_NAME=cookie \
    WAF_COOKIE_PROFILES=/app/profiles \
    WAF_COOKIE_DATA=/var/lib/waf/cookie \
    WAF_COOKIE_LOG=info

# CMD, а не ENTRYPOINT: как у остальных инспекторов, и `docker run <образ> sh`
# остаётся рабочим способом заглянуть внутрь.
# Проба идёт тем же путём, что запрос модуля: шина, подписка, профили,
# воркеры. Профиль default, вердикт любой -- здоровье, а не решение.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["cookie-probe", "--quiet", "--timeout", "1s"]
CMD ["cookie"]
