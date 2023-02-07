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
ENV GOPRIVATE github.com/m4rkdc/nebula_est/*
RUN git config --global url.ssh://git@github.com/.insteadOf https://github.com/
RUN mkdir /root/.ssh && ssh-keyscan github.com >> /root/.ssh/known_hosts
RUN --mount=type=secret,id=sshKey,dst=/root/.ssh/id_ed25519 go build -o ./nest_ca ./cmd/*

#RUN go build -o ./nest_ca ./cmd/*

# Deployment phase
FROM alpine:3.17
WORKDIR /home/nest_ca
EXPOSE 4242/udp
EXPOSE 53535/tcp
RUN apk add --no-cache libc6-compat
COPY --from=build /home/nest_build/nest_ca ./nest_ca
ENTRYPOINT ["./nest_ca"]
