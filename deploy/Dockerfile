FROM golang:1.25-alpine AS build

WORKDIR /src

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/cookie ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/cookie-probe ./cmd/probe

FROM alpine:3.22

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

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["cookie-probe", "--quiet", "--timeout", "1s"]
CMD ["cookie"]
