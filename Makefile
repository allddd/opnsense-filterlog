# Copyright (c) 2025, 2026 allddd <me@allddd.onl>
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

.PHONY: all build build-release clean deps help install lint release test test-gen uninstall

GO ?= go
INSTALL ?= install
INSTALL_DATA ?= $(INSTALL) -m 644
INSTALL_PROGRAM ?= $(INSTALL)

PREFIX ?= /usr/local
EXEC_PREFIX ?= $(PREFIX)
SBINDIR ?= $(EXEC_PREFIX)/sbin
DATAROOTDIR ?= $(PREFIX)/share
MANDIR ?= $(DATAROOTDIR)/man
MAN8DIR ?= $(MANDIR)/man8

PROGRAM ?= opnsense-filterlog
VERSION != git describe --tags 2>/dev/null || printf 'unknown'
# needed for gmake < 4.0
VERSION ?= $(shell git describe --tags 2>/dev/null || printf 'unknown')
GO_LDFLAGS ?= -X 'gitlab.com/allddd/opnsense-filterlog/internal/meta.Name=$(PROGRAM)' \
              -X 'gitlab.com/allddd/opnsense-filterlog/internal/meta.Version=$(VERSION)'

all: build ## run build

build: ## build binary
	CGO_ENABLED=0 $(GO) build -trimpath -mod=readonly -ldflags="$(GO_LDFLAGS)" -o ./$(PROGRAM) ./

build-release: clean ## build release binary
	$(GO) mod verify
	CGO_ENABLED=0 GOARCH=amd64 GOOS=freebsd $(GO) build -trimpath -buildvcs=false -mod=readonly -ldflags="$(GO_LDFLAGS) -s -w -buildid=" -o ./$(PROGRAM) ./

clean: ## remove build artifacts
	rm -f ./$(PROGRAM)

deps: ## update dependencies
	$(GO) mod tidy
	$(GO) get -u ./...
	$(GO) mod tidy
	$(GO) mod verify

help: ## display help message
	@printf 'available targets:\n'
	@awk -F' ## ' '/^[a-z-]+:.+##/ {sub(/:.*/, "", $$1); printf "  %-15s - %s\n", $$1, $$2}' ./Makefile

install: ## install files
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROGRAM) ./$(PROGRAM) $(DESTDIR)$(SBINDIR)/$(PROGRAM)
	$(INSTALL) -d $(DESTDIR)$(MAN8DIR)
	$(INSTALL_DATA) ./docs/$(PROGRAM).8 $(DESTDIR)$(MAN8DIR)/$(PROGRAM).8

lint: ## format code and run linters
	golangci-lint fmt
	golangci-lint run

release: build-release ## create release
	@git branch --show-current | grep -qx master || (printf 'error: not on master branch\n'; exit 1)
	@git describe --exact-match HEAD >/dev/null 2>&1 || (printf 'error: HEAD not tagged\n'; exit 1)
	@! git ls-remote -t --exit-code origin $(VERSION) >/dev/null 2>&1 || (printf 'error: tag $(VERSION) already exists\n'; exit 1)
	@curl -fsSL 'https://go.dev/dl/?mode=json' | jq -r '.[0].version' | grep -qx "$$($(GO) version -m -json $$(which $(GO)) | jq -r '.GoVersion')" || (printf 'error: not using latest go version\n'; exit 1)
	git push origin $(VERSION)
	sleep 10
	glab ci status -lb $(VERSION)
	glab job artifact -p ./artifacts/ $(VERSION) build
	cmp ./$(PROGRAM) ./artifacts/$(PROGRAM) || (rm -rf ./artifacts; exit 1)
	rm -rf ./artifacts
	sha256sum $(PROGRAM) | gpg --clearsign > ./$(PROGRAM).sha256
	glab release upload --use-package-registry --package-name $(PROGRAM) $(VERSION) ./$(PROGRAM).sha256

test: build ## run tests
	$(GO) test -fullpath -mod=readonly -shuffle=on ./...

test-gen: build ## generate golden files for tui tests
	$(GO) test -fullpath -mod=readonly ./internal/tui/ -update

uninstall: ## remove installed files
	rm -f $(DESTDIR)$(SBINDIR)/$(PROGRAM)
	rm -f $(DESTDIR)$(MAN8DIR)/$(PROGRAM).8
