# syntax=docker/dockerfile:1

FROM golang:1.26.11-alpine AS builder

ARG GOPROXY=https://proxy.golang.org,direct
ARG APP_VERSION=dev

ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -ldflags="-s -w -X main.appVersion=${APP_VERSION}" -o /out/awsquick2api ./cmd/awsquick2api

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 -S app \
    && adduser -u 10001 -S -G app -h /app app \
    && mkdir -p /app/storage \
    && chown -R 10001:10001 /app

COPY --from=builder /out/awsquick2api /usr/local/bin/awsquick2api

WORKDIR /app
ENV AWSQUICK_LISTEN=0.0.0.0:8045 \
    AWSQUICK_NO_TRAY=1

EXPOSE 8045
VOLUME ["/app/storage"]
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD sh -c 'PORT="${AWSQUICK_LISTEN##*:}"; wget -q -T 3 -O /dev/null "http://127.0.0.1:${PORT:-8045}/healthz"' || exit 1

ENTRYPOINT ["/usr/local/bin/awsquick2api"]
CMD ["-config", "/app/storage/config.json"]
