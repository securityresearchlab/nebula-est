FROM alpine:3.17
WORKDIR /home/nest_service
COPY ./build/nest_service .
EXPOSE 8080/tcp
EXPOSE 4242/udp
RUN apk add --no-cache libc6-compat
ENTRYPOINT ["./nest_service"]
