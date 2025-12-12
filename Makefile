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

.PHONY: build build-release clean deps fmt help install modernize release test uninstall

PROGRAM = opnsense-filterlog
VERSION != git describe --tags 2>/dev/null || printf 'unknown'
# needed for gmake < 4.0
VERSION ?= $(shell git describe --tags 2>/dev/null || printf 'unknown')
LDFLAGS = -X 'gitlab.com/allddd/opnsense-filterlog/internal/meta.Name=$(PROGRAM)' \
          -X 'gitlab.com/allddd/opnsense-filterlog/internal/meta.Version=$(VERSION)'

PREFIX = /usr/local
EXEC_PREFIX = $(PREFIX)
SBINDIR = $(EXEC_PREFIX)/sbin
DATAROOTDIR = $(PREFIX)/share
MANDIR = $(DATAROOTDIR)/man
MAN8DIR = $(MANDIR)/man8

GO = go
INSTALL = install
INSTALL_DATA = $(INSTALL) -m 644
INSTALL_PROGRAM = $(INSTALL)

build: ## build development binary (default)
	$(GO) build -ldflags "$(LDFLAGS)" -o ./$(PROGRAM) ./

build-release: ## build release binary
	CGO_ENABLED=0 GOARCH=amd64 GOOS=freebsd $(GO) build -trimpath -ldflags "$(LDFLAGS) -s -w -buildid=" -o ./$(PROGRAM) ./

clean: ## remove build artifacts
	rm -f ./$(PROGRAM)

deps: ## update dependencies
	$(GO) get -u ./...
	$(GO) mod tidy
	$(GO) mod verify

fmt: ## format code
	$(GO) fmt ./...

help: ## display help message
	@printf 'available targets:\n'
	@awk -F' ## ' '/^[a-z-]+:/ {sub(/:.*/, "", $$1); printf "  %-15s - %s\n", $$1, $$2}' ./Makefile

install: build-release ## build and install files
	$(INSTALL) -d $(DESTDIR)$(SBINDIR)
	$(INSTALL_PROGRAM) ./$(PROGRAM) $(DESTDIR)$(SBINDIR)/$(PROGRAM)
	$(INSTALL) -d $(DESTDIR)$(MAN8DIR)
	$(INSTALL_DATA) ./docs/$(PROGRAM).8 $(DESTDIR)$(MAN8DIR)/$(PROGRAM).8

modernize: ## modernize code
	$(GO) run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -diff ./...

release: fmt modernize test clean build-release ## create signed release
	sha256sum $(PROGRAM) | gpg --clearsign > ./$(PROGRAM).sha256

test: ## run tests
	$(GO) test -fullpath -shuffle=on ./...

uninstall: ## remove installed files
	rm -f $(DESTDIR)$(SBINDIR)/$(PROGRAM)
	rm -f $(DESTDIR)$(MAN8DIR)/$(PROGRAM).8
