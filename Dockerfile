# The builder contains compilers and is discarded; only the distroless runtime
# stage is shipped. Keep the pinned Go minor current as fixes become available.
FROM golang:1.26-alpine3.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/permissions-server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/permissions-server /app/permissions-server
VOLUME ["/data"]
EXPOSE 8088
ENTRYPOINT ["/app/permissions-server"]
