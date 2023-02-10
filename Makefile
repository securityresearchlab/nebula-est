.PHONY: nest_service nest_ca nest_config

nest_service:
	cd nest_service; mkdir build; go build -o ./build cmd/*; env GOOS=linux GOARCH=arm go build -o ./build/nest_service_arm cmd/*

nest_ca:
	cd nest_ca;	mkdir build; go build -o ./build cmd/*;	env GOOS=linux GOARCH=arm go build -o ./build/nest_ca_arm cmd/*

nest_config:
	cd nest_config;	mkdir build; go build -o ./build cmd/*; env GOOS=linux GOARCH=arm go build -o ./build/nest_config_arm cmd/*;

nest_client_lin_64:
	cd nest_client;	mkdir build; env GOOS=linux GOARCH=amd64 go build -o ./build/nest_client_lin_64 cmd/*

nest_client_lin_32:
	cd nest_client;	mkdir build; env GOOS=linux GOARCH=386 go build -o ./build/nest_client_lin_386 cmd/*

nest_client_win:
	cd nest_client;	mkdir build; env GOOS=windows GOARCH=amd64 go build -o ./build/nest_client_win.exe cmd/*

nest_client_lin_arm:
	cd nest_client;	mkdir build; env GOOS=linux GOARCH=arm go build -o ./build/nest_client_lin_arm cmd/*

nest_services: nesst_service nest_ca nest_config

nest_clients: nest_client_lin_64 nest_client_lin_32 nest_client_lin_arm nest_client_win

all: nest_service nest_ca nest_config nest_clients

# Docker builds

nest_service_docker:
	cd nest_service; docker build --rm \
		-t nest_service \
		. ; cd ..

nest_ca_docker:
	cd nest_ca; docker build --rm \
        -t nest_ca \
        --secret id=sshKey,src=${HOME}/.ssh/github_ed25519 \
        . ; cd ..

nest_config_docker:
	cd nest_config; docker build --rm \
        -t nest_config \
        --secret id=sshKey,src=${HOME}/.ssh/github_ed25519 \
        . ; cd .. 

nest_client_lin_64_docker:
	cd nest_client; docker build --rm \
        -t nest_client_lin_64 \
        -f Dockerfile_lin_64 \
		--secret id=sshKey,src=${HOME}/.ssh/github_ed25519 \
		. ; cd ..

nest_client_lin_386_docker:
	cd nest_client; docker build --rm \
		-t nest_client_lin_386 \
		-f Dockerfile_lin_386 \
		--secret id=sshKey,src=${HOME}/.ssh/github_ed25519 \
		. ; cd ..

nest_client_lin_arm_docker:
	cd nest_client; docker build --rm \
		-t nest_client_lin_arm \
		-f Dockerfile_lin_arm \
		--secret id=sshKey,src=${HOME}/.ssh/github_ed25519 \
		. ; cd ..

nest_services_docker: nest_ca_docker nest_config_docker nest_service_docker 

nest_clients_docker: nest_client_lin_64_docker nest_client_lin_386_docker nest_client_lin_arm_docker

all_docker: nest_services_docker nest_clients_docker