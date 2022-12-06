#!/bin/bash

cd nest_service
mkdir build
go build -o ./build cmd/*
docker build --rm -t nest_service .

cd ../nest_ca
mkdir build
go build -o ./build cmd/*
docker build --rm -t nest_ca .

cd ../nest_config
mkdir build
go build -o ./build cmd/*
docker build --rm -t nest_config .

#cd ../nest_client
#mkdir build
#go build -o ./build cmd/*
#docker build -t nest_client .
