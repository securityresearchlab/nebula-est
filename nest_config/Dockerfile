FROM alpine:3.17
WORKDIR /home/nest_config
COPY ./build/nest_config .
EXPOSE 61616/tcp
EXPOSE 4242/udp
RUN apk add --no-cache libc6-compat
RUN apk add --no-cache ncurses-libs
RUN ln -s -f /usr/lib/libncursesw.so.6 /usr/lib/libtinfo.so.6
RUN apk add --no-cache gmp
ENTRYPOINT ["./nest_config"]