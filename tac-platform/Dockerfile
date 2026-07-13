# Build the tac-platform binaries (tacctl human CLI + crash-executor test helper).
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/tacctl ./cmd/tacctl \
 && CGO_ENABLED=0 go build -o /out/crash-executor ./cmd/crash-executor

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/tacctl /app/tacctl
COPY --from=build /out/crash-executor /app/crash-executor
ENTRYPOINT ["/app/tacctl"]
