# Real Culvert proxy binary in the same runtime shape as Culvert's
# test/e2e/maint-agent/Dockerfile.e2e final stage. The binary is built outside
# (go build of the pinned source) and copied in; nothing here patches it.
FROM alpine:3.24
# No apk step: the build sandbox has no package network; busybox provides wget.
RUN addgroup -S proxy && adduser -S proxy -G proxy \
    && mkdir -p /data /backup && chown proxy:proxy /data /backup
USER proxy
WORKDIR /app
COPY --chown=proxy:proxy culvert .
VOLUME ["/data"]
EXPOSE 8080 9090
ENTRYPOINT ["./culvert"]
