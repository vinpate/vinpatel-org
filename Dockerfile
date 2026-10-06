FROM --platform=$BUILDPLATFORM golang:1.27.1-trixie@sha256:3b77fc618ec235a1ab412de7737f120dd507c57e8d87de4cbb7994fb94275ed5 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG BUILD_TIME=
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION} -X main.buildTime=${BUILD_TIME}" \
    -o /out/server ./cmd/server

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/server /server
USER 65534:65534
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --start-interval=1s --retries=3 \
    CMD ["/server", "-healthcheck"]
ENTRYPOINT ["/server"]
