FROM alpine:3.14
WORKDIR /home/nest_config
COPY ./build/nest_config .
EXPOSE 61616/tcp
EXPOSE 4242/udp
RUN apk add --no-cache libc6-compat
ENTRYPOINT ["./nest_config"]