# Build stage
FROM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS builder

WORKDIR /src
RUN apk --no-cache add ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -extldflags '-static'" \
    -o /bin/logzero \
    ./cmd/logzero

# Production stage — distroless static, pinned by digest
# Update this digest when upgrading the base image
FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

COPY --from=builder /bin/logzero /bin/logzero

# Run as non-root (65534 is the 'nonroot' user in distroless)
USER 65534:65534

ENTRYPOINT ["/bin/logzero"]
CMD ["--help"]
