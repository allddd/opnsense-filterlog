.PHONY: build clean deps fmt help release test

BINARY_NAME := opnsense-filterlog
LDFLAGS := -X 'main.Version=$(VERSION)'
VERSION ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf 'dev')_$(shell date --iso-8601=seconds)

build: ## build the binary (default)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS) -s -w -buildid=" -o ./$(BINARY_NAME) ./

clean: ## remove build artifacts
	rm -f ./$(BINARY_NAME)

deps: ## update dependencies
	go get -u ./...
	go mod tidy
	go mod verify

fmt: ## format code
	go fmt ./...

help: ## display this help message
	@printf "available targets:\n\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf " %-10s - %s\n", $$1, $$2}'

release: clean fmt test build ## same as clean + fmt + test + build

test: ## run tests
	go test -v ./...
