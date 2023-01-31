#!/bin/bash

cd nest_service
mkdir build
go build -o ./build cmd/*
env GOOS=linux GOARCH=arm go build -o ./build/nest_service_arm cmd/*
docker build --rm -t nest_service .

cd ../nest_ca
mkdir build
go build -o ./build cmd/*
env GOOS=linux GOARCH=arm go build -o ./build/nest_ca_arm cmd/*
docker build --rm -t nest_ca .

cd ../nest_config
mkdir build
go build -o ./build cmd/*
env GOOS=linux GOARCH=arm go build -o ./build/nest_config_arm cmd/*
docker build --rm -t nest_config .

cd ../nest_client
mkdir build
env GOOS=windows GOARCH=amd64 go build -o ./build/nest_client_win.exe cmd/*
env GOOS=linux GOARCH=amd64 go build -o ./build/nest_client_lin_64 cmd/*
env GOOS=linux GOARCH=386 go build -o ./build/nest_client_lin_386 cmd/*
env GOOS=linux GOARCH=arm go build -o ./build/nest_client_lin_arm cmd/*
env GOOS=linux GOARCH=arm go build -o ./build/nest_client_android cmd/*
docker build -t nest_client_lin_64 -f ./Dockerfile_lin_64 .
docker build -t nest_client_lin_386 -f ./Dockerfile_lin_386 .
#docker build -t nest_client_android -f ./Dockerfile_android .
