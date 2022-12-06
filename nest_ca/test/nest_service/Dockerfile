# syntax=docker/dockerfile:1
FROM golang:1.19-alpine AS build
WORKDIR /nest_service
COPY ./build/nest_service .
EXPOSE 8080/tcp
ENTRYPOINT ["./nest_service"]
