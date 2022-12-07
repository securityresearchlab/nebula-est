FROM alpine:3.17
WORKDIR /home/nest_ca
COPY ./build/nest_ca .
EXPOSE 4242/udp
EXPOSE 53535/tcp
RUN apk add --no-cache libc6-compat
ENTRYPOINT ["./nest_ca"]