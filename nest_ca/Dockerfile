# Building phase
FROM golang:1.20.0-alpine3.17 AS build
WORKDIR /home/nest_build
COPY go.mod go.sum ./
RUN export GOPATH=/home/nest_build 
ADD ./cmd ./cmd
ADD ./pkg ./pkg
RUN mkdir /home/nest_service/pkg/
ADD ../nest_service/pkg/utils /home/nest_service/pkg/utils
ADD ../nest_service/pkg/models /home/nest_service/pkg/models
RUN go build -o ./nest_ca ./cmd/*

# Deployment phase
FROM alpine:3.17
WORKDIR /home/nest_ca
COPY --from=build /home/nest_build/nest_ca ./nest_ca
EXPOSE 4242/udp
EXPOSE 53535/tcp
RUN apk add --no-cache libc6-compat
ENTRYPOINT ["./nest_ca"]
