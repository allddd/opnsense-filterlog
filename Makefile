# Copyright (c) 2025 allddd <me@allddd.onl>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

.PHONY: build build-release clean deps fmt help modernize release test

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

modernize: ## modernize code
	go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -diff ./...

release: fmt modernize test clean build-release ## create signed release
	sha256sum $(BINARY_NAME) | gpg --clearsign > ./$(BINARY_NAME).sha256

test: ## run tests
	go test -fullpath -shuffle=on ./...
