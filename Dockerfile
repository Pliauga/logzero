# Build stage
FROM golang:1.22-alpine AS builder

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
# ASSUMPTION: Using latest known digest for gcr.io/distroless/static:nonroot
# Update this digest when upgrading the base image
FROM gcr.io/distroless/static:nonroot@sha256:6ec5aa99dc335b8d8f71b85c9088c2ff8637b56a7d3e2e01a543e736ab44b519

COPY --from=builder /bin/logzero /bin/logzero

# Run as non-root (65534 is the 'nonroot' user in distroless)
USER 65534:65534

ENTRYPOINT ["/bin/logzero"]
CMD ["--help"]
