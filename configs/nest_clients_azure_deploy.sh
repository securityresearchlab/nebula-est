#!/bin/bash
generate_configs_client(){
    mkdir nest_client_lin_64 nest_client_lin_386 nest_client_android lighthouse nest_client_win
    mkdir nest_client_lin_64/config nest_client_lin_386/config nest_client_android/config lighthouse/config nest_client_win/config
    cat nest_service/config/hmac.key
    echo -n "nest_client_lin_64" | openssl dgst -sha256 -hmac $(<nest_service/config/hmac.key) | sed "s/(stdin)= //"| tr -d "\n" > nest_client_lin_64/config/secret.hmac
    echo -n "nest_client_lin_386" | openssl dgst -sha256 -hmac $(<nest_service/config/hmac.key) | sed "s/(stdin)= //"| tr -d "\n" > nest_client_lin_386/config/secret.hmac
    echo -n "nest_client_android" | openssl dgst -sha256 -hmac $(<nest_service/config/hmac.key) | sed "s/(stdin)= //"| tr -d "\n" > nest_client_android/config/secret.hmac
    echo -n "lighthouse" | openssl dgst -sha256 -hmac $(<nest_service/config/hmac.key) | sed "s/(stdin)= //"| tr -d "\n" > lighthouse/config/secret.hmac
    echo -n "nest_client_win" | openssl dgst -sha256 -hmac $(<nest_service/config/hmac.key) | sed "s/(stdin)= //"| tr -d "\n" > nest_client_win/config/secret.hmac
    mkdir nest_client_lin_64/config/tls nest_client_lin_386/config/tls nest_client_android/config/tls lighthouse/config/tls nest_client_win/config/tls
    cp nest_service/config/tls/nest_service-crt.pem nest_client_lin_386/config/tls/ 
    cp nest_service/config/tls/nest_service-crt.pem nest_client_lin_64/config/tls/
    cp nest_service/config/tls/nest_service-crt.pem nest_client_android/config/tls/
    cp nest_service/config/tls/nest_service-crt.pem lighthouse/config/tls/
    cp nest_service/config/tls/nest_service-crt.pem nest_client_win/config/tls/
    mkdir nest_client_lin_64/bin nest_client_lin_386/bin nest_client_android/bin lighthouse/bin nest_client_win/bin
    cp nest_service/config/nebula/nebula nest_client_lin_64/bin/
    cp nest_ca/config/bin/nebula-cert nest_client_lin_64/bin/
    cd nest_client_lin_386/bin/
    wget https://github.com/slackhq/nebula/releases/download/v1.6.1/nebula-linux-386.tar.gz && tar -xzvf  nebula-linux-386.tar.gz && rm nebula-linux-386.tar.gz && rm nebula-cert
    cd ../../nest_client_android/bin
    wget https://github.com/slackhq/nebula/releases/download/v1.6.1/nebula-linux-arm64.tar.gz && tar -xzvf  nebula-linux-arm64.tar.gz && rm nebula-linux-arm64.tar.gz 
    cp nebula nebula-cert ../../lighthouse/bin && rm nebula-cert
    cd ../../nest_client_win/bin
    wget https://github.com/slackhq/nebula/releases/download/v1.6.1/nebula-windows-amd64.zip &&  unzip nebula-windows-amd64.zip && rm nebula-windows-amd64.zip && rm -r dist/

    cd ../../
    cp ../examples/azure/client/*.env .
    echo "1" > done_gen_client
    
}

if [ ! -f ./done_gen_client ]; then
    echo "Configs are not present, generating..."
    generate_configs_client
fi

docker compose -p "nest_clients" -f docker-compose-azure-clients.yaml up -d