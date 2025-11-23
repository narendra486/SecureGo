# Build single-server demo
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /out/single-server demo/single-server.go

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/single-server /app/single-server
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/single-server"]
