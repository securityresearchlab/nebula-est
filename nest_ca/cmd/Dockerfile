FROM golang:1.19-alpine AS build
WORKDIR /nest_ca
COPY ../../build/nest_ca ./nest_ca
EXPOSE 53535/tcp
ENTRYPOINT ["./nest_ca"]