FROM golang:alpine AS builder

RUN mkdir /app
ADD . /app/
WORKDIR /app
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s"
CMD ["./piot-mosquitto-auth"]

FROM alpine:latest AS alpine
COPY --from=builder /app/piot-mosquitto-auth /app/piot-mosquitto-auth
WORKDIR /app/
EXPOSE 9095
CMD ["./piot-mosquitto-auth"]
