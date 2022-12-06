FROM golang:1.19-alpine AS build
WORKDIR /nest_config
COPY ../../build/nest_config .
EXPOSE 61616/tcp
ENTRYPOINT ["./nest_config"]