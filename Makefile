.PHONY: build build-release clean deps fmt help release test

BINARY_NAME := opnsense-filterlog
VERSION != git describe --tags 2>/dev/null || printf 'dev'
VERSION ?= $(shell git describe --tags 2>/dev/null || printf 'dev')
LDFLAGS := -X 'main.Version=$(VERSION)'

build: ## build development binary (default)
	go build -ldflags "$(LDFLAGS)" -o ./$(BINARY_NAME) ./

build-release: ## build release binary
	CGO_ENABLED=0 GOARCH=amd64 GOOS=freebsd go build -trimpath -ldflags "$(LDFLAGS) -s -w -buildid=" -o ./$(BINARY_NAME) ./

clean: ## remove build artifacts
	rm -f ./$(BINARY_NAME)

deps: ## update dependencies
	go get -u ./...
	go mod tidy
	go mod verify

fmt: ## format code
	go fmt ./...

help: ## display this help message
	@printf 'available targets:\n\n'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf " %-15s - %s\n", $$1, $$2}'

release: clean fmt test build-release ## create signed release
	sha256sum $(BINARY_NAME) | gpg --clearsign > ./$(BINARY_NAME).sha256

test: ## run tests
	go test -fullpath -shuffle=on ./...
