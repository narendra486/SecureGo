# Build demo server
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /out/demo demo/demo.go

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/demo /app/demo
EXPOSE 1337
USER nonroot:nonroot
ENTRYPOINT ["/app/demo"]
