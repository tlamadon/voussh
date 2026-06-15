# Build the voussh server as a static binary.
FROM golang:1.24-alpine AS build

WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Version stamped into the binary (the build context excludes .git, so the
# Go VCS fallback isn't available here — pass it explicitly).
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
	-ldflags="-s -w -X github.com/voussh/voussh/internal/version.Version=${VERSION}" \
	-o /out/voussh ./cmd/voussh

# Minimal runtime image. Includes CA certificates for outbound TLS to Google
# OIDC. Runs as root so it can read a bind-mounted CA key with 0600 perms.
FROM gcr.io/distroless/static-debian12:latest

WORKDIR /data
EXPOSE 8080

COPY --from=build /out/voussh /usr/local/bin/voussh

ENTRYPOINT ["voussh"]
CMD ["--config", "/data/config.yaml"]
