nest_service:
	cd nest_service; mkdir build; go build -o ./build cmd/*; env GOOS=linux GOARCH=arm go build -o ./build/nest_service_arm cmd/*

nest_ca:
	cd nest_ca;	mkdir build; go build -o ./build cmd/*;	env GOOS=linux GOARCH=arm go build -o ./build/nest_ca_arm cmd/*

nest_config:
	cd nest_config;	mkdir build
	go build -o ./build cmd/*; env GOOS=linux GOARCH=arm go build -o ./build/nest_config_arm cmd/*;

nest_client_lin_64:
	cd nest_client;	mkdir build; env GOOS=linux GOARCH=amd64 go build -o ./build/nest_client_lin_64 cmd/*

nest_client_lin_32:
	cd nest_client;	mkdir build; env GOOS=linux GOARCH=386 go build -o ./build/nest_client_lin_386 cmd/*

nest_client_windows:
	cd nest_client;	mkdir build; env GOOS=windows GOARCH=amd64 go build -o ./build/nest_client_windows cmd/*

nest_client_lin_arm:
	cd nest_client;	mkdir build; env GOOS=linux GOARCH=arm go build -o ./build/nest_client_lin_arm cmd/*

nest_clients: nest_client_lin_64 nest_client_lin_32 nest_client_lin_arm nest_client_windows

all: nest_service nest_ca nest_config nest_clients