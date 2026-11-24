FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ferry ./cmd/ferry

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates openvpn iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /ferry /usr/local/bin/ferry
ENTRYPOINT ["/usr/local/bin/ferry"]
