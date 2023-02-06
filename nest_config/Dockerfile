# Building phase
FROM golang:1.20.0-alpine3.17 AS build
WORKDIR /home/nest_build
COPY go.mod go.sum ./
RUN export GOPATH=/home/nest_build   
ADD ./cmd ./cmd
ADD ./pkg ./pkg
ADD ../nest_service/pkg ../nest_service/pkg
RUN go build -o ./nest_config ./cmd/*

# Deployment phase
FROM alpine:3.17
WORKDIR /home/nest_config
COPY --from=build /home/nest_build/nest_config ./nest_config
EXPOSE 61616/tcp
EXPOSE 4242/udp
RUN apk add --no-cache libc6-compat
RUN apk add --no-cache ncurses-libs
RUN ln -s -f /usr/lib/libncursesw.so.6 /usr/lib/libtinfo.so.6
RUN apk add --no-cache gmp
ENTRYPOINT ["./nest_config"]

