# Stage 1: Build Go binary
FROM golang:1.22 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /opa-sidecar .

# Stage 2: Lightweight runtime with nc for healthcheck
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
WORKDIR /
COPY --from=builder /opa-sidecar .
COPY policies/ /policies/
EXPOSE 9191 9192
ENTRYPOINT ["/opa-sidecar"]
