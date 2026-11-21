# syntax=docker/dockerfile:1
# Deferred hosted surface (enki-cloud); the CLI release does not ship this image.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/enki-cloud ./cmd/enki-cloud

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/enki-cloud /usr/local/bin/enki-cloud
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/enki-cloud"]
