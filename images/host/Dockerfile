# Probe host: Alpine with iproute2, iputils, tcpdump and the Go prober.
FROM golang:1.26.11-alpine AS build
WORKDIR /src
COPY go/go.mod go/go.sum ./
RUN go mod download
COPY go/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/prober ./cmd/prober

FROM alpine:3.24.4
RUN apk add --no-cache iproute2 iputils tcpdump
COPY --from=build /out/prober /usr/local/bin/prober
CMD ["sleep", "infinity"]
