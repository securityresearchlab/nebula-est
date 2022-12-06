#!/bin/bash

generate_configs(){
wget https://github.com/slackhq/nebula/releases/download/v1.6.1/nebula-linux-amd64.tar.gz && tar -xzvf  nebula-linux-amd64.tar.gz && rm nebula-linux-amd64.tar.gz
nebula-cert ca -name "nest_system_ca" -out-crt nest_system_ca.crt -out-key nest_system_ca.key

mkdir nest_ca nest_service nest_config

cd nest_ca
mkdir log config certificates
cd config
mkdir bin && cd bin
cp ../../../nebula-cert .
cd ../
mkdir keys && cd keys
../bin/nebula-cert ca -name "ca" -out-crt ca.crt -out-key ca.key
cd ../
mkdir nebula && cd nebula
cp ../../../nest_system_ca.crt ../../../nebula .
../bin/nebula-cert sign -ip 192.168.80.1/24 -name nest_ca -ca-key ../../../nest_system_ca.key -ca-crt nest_system_ca.crt

cd ../../../nest_config
mkdir log config dhall
cd dhall/
cp -rf ../../../examples/client/* .
cd ../config
mkdir nebula && cd nebula
cp ../../../nest_system_ca.crt ../../../nebula .
../../../nebula-cert sign -ip 192.168.80.2/24 -name nest_config -ca-key ../../../nest_system_ca.key -ca-crt nest_system_ca.crt

cd ../../../nest_service
mkdir log config
cd config
mkdir tls && cd tls
# If you want to self-sign your nest_service tls certificate
#openssl ecparam -name secp256k1 -genkey -noout -out nest_service-key.pem
#openssl req -new -x509 -key nest_service-key.pem -out nest_service-crt.pem -days 365

# If you want to use an already created internal CA, first copy it in the configs folder, then
openssl ecparam -name secp256k1 -genkey -noout -out nest_service-key.pem
openssl req -new -sha256 -key nest_service-key.pem -out nest_service.csr
openssl x509 -signkey ../../../ca-key.pem -in nest_service.csr -req -days 365 -out nest_service-crt.pem
rm nest_service.csr

cd ../
mkdir nebula && cd nebula
cp ../../../nest_system_ca.crt ../../../nebula .
../../../nebula-cert sign -ip 192.168.80.3/24 -name nest_service -ca-key ../../../nest_system_ca.key -ca-crt nest_system_ca.crt

cd ../
head /dev/urandom | sha256sum > hmac.key

cd ../../
rm nebula* *.crt *.key
cp ../examples/system/*.env .
cp ../examples/system/nest_service.yml nest_service/config/nebula/config.yml
cp ../examples/system/nest_ca.yml nest_ca/config/nebula/config.yml
cp ../examples/system/nest_config.yml nest_config/config/nebula/config.yml
echo 1 > done_gen
}

if [ ! -f ./done_gen ]; then
    echo "Configs are not present, generating..."
    generate_configs
fi 

docker compose up -d
