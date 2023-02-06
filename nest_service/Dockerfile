# Building phase
FROM golang:1.20.0-alpine3.17 AS build
WORKDIR /home/nest_build
COPY go.mod go.sum ./
RUN export GOPATH=/home/nest_build
# RUN go mod download && go mod verify    
ADD ./cmd ./cmd
ADD ./pkg ./pkg
RUN go build -o ./nest_service ./cmd/*

# Deployment phase
FROM alpine:3.17
WORKDIR /home/nest_service
COPY --from=build /home/nest_build/nest_service ./nest_service
EXPOSE 8080/tcp
EXPOSE 4242/udp
RUN apk add --no-cache libc6-compat
ENTRYPOINT ["./nest_service"]