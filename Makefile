.PHONY: build clean down generate reset test up

generate:
	go generate ./api

build: generate
	go build ./...

test: generate
	go test ./...

up:
	docker compose up --build

down:
	docker compose down

reset:
	docker compose down --volumes

clean:
	rm -rf bin data/*.db data/*.db-*