FROM golang:1.21 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends git gcc libc6-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Clone glauth at pinned version
RUN git clone --depth 1 --branch v2.4.0 \
    https://github.com/glauth/glauth /build/glauth

# Copy plugin source
COPY . /build/plugin

# Build glauth binary (CGO_ENABLED=1 needed so plugin loading works at runtime)
RUN cd /build/glauth/v2 && CGO_ENABLED=1 go build -o /app/glauth .

# Build plugin .so — must use same module as glauth via replace directive
# Plugins always require CGO
RUN cd /build/plugin && \
    go mod edit -replace github.com/glauth/glauth/v2=/build/glauth/v2 && \
    go mod tidy && \
    CGO_ENABLED=1 go build -buildmode=plugin -o /app/pocketid.so .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates gettext-base && rm -rf /var/lib/apt/lists/*

RUN groupadd -r glauth && useradd -r -g glauth -d /var/lib/glauth -s /sbin/nologin glauth

COPY --from=builder /app/glauth /app/glauth
COPY --from=builder /app/pocketid.so /app/pocketid.so
COPY docker/glauth.cfg.tmpl /etc/glauth/glauth.cfg.tmpl
COPY docker/glauth.cfg.example /etc/glauth/glauth.cfg
COPY docker/entrypoint.sh /app/entrypoint.sh

RUN mkdir -p /var/lib/glauth && chown glauth:glauth /var/lib/glauth && \
    chown -R glauth:glauth /etc/glauth

USER glauth
EXPOSE 3893

ENTRYPOINT ["/app/entrypoint.sh"]
