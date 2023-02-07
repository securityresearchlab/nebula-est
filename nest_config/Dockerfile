# Building phase
FROM golang:1.20.0-alpine3.17 AS build
WORKDIR /home/nest_build
COPY go.mod go.sum ./
RUN export GOPATH=/home/nest_build   
ADD ./cmd ./cmd
ADD ./pkg ./pkg

# Following lines are for authentication to git private repo
RUN apk add git
RUN apk add openssh
RUN git config --global url.ssh://git@github.com/.insteadOf https://github.com/
RUN mkdir /root/.ssh && ssh-keyscan github.com >> /root/.ssh/known_hosts
ENV GOPRIVATE github.com/m4rkdc/nebula_est/*
RUN --mount=type=secret,id=sshKey,dst=/root/.ssh/id_ed25519 go build -o ./nest_config ./cmd/*

#RUN go build -o ./nest_config ./cmd/*

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

