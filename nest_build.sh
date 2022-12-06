#!/bin/bash

mkdir ./build
for f in $(ls */cmd/*.go); do
    go build -o ./build $f
done