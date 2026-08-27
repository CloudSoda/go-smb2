# Development tasks. The integration tests need a real SMB server, so most
# targets here are about getting one running and pointing the tests at it.

SMB_PORT       ?= 4445
SMB_IMAGE      ?= go-smb2-samba:test
SMB_CONTAINER  ?= go-smb2-samba
COVER_PROFILE  ?= coverage.out
# Ratcheted upward as tests land. It records where the suite is, not where
# it ought to be.
COVER_MIN      ?= 56

.PHONY: all
all: lint test

# Build the Samba image used by the integration tests.
.PHONY: samba-build
samba-build:
	docker build -t $(SMB_IMAGE) .github/docker

# Start the Samba server and write a client config pointing at it.
.PHONY: samba-up
samba-up: samba-build
	@docker rm -f $(SMB_CONTAINER) >/dev/null 2>&1 || true
	docker run -d --name $(SMB_CONTAINER) -p $(SMB_PORT):445 $(SMB_IMAGE)
	@sed 's/"port": 445/"port": $(SMB_PORT)/' .github/client_conf.json > client_conf.json
	@printf 'waiting for samba on port $(SMB_PORT)'
	@for i in $$(seq 1 30); do \
		if nc -z 127.0.0.1 $(SMB_PORT) 2>/dev/null; then echo " ready"; exit 0; fi; \
		printf '.'; sleep 1; \
	done; \
	echo " timed out"; docker logs $(SMB_CONTAINER); exit 1

.PHONY: samba-down
samba-down:
	@docker rm -f $(SMB_CONTAINER) >/dev/null 2>&1 || true
	@rm -f client_conf.json

# Unit tests only. No server needed.
.PHONY: unit
unit:
	go test -race -count=1 ./internal/...

# Full suite, including the integration tests, against a throwaway server.
.PHONY: test
test: samba-up
	@go test -race -count=1 ./... ; status=$$? ; $(MAKE) samba-down ; exit $$status

# Full suite with a coverage profile, then enforce the minimum.
.PHONY: cover
cover: samba-up
	@go test -count=1 -coverprofile=$(COVER_PROFILE) -covermode=atomic -coverpkg=./... ./... ; \
		status=$$? ; $(MAKE) samba-down ; \
		if [ $$status -ne 0 ]; then exit $$status; fi
	@go tool cover -func=$(COVER_PROFILE) | tail -1
	@$(MAKE) cover-check

# Fail if total statement coverage is below COVER_MIN.
.PHONY: cover-check
cover-check:
	@total=$$(go tool cover -func=$(COVER_PROFILE) | awk '/^total:/ {print $$3}' | tr -d '%') ; \
		echo "total coverage: $$total% (minimum $(COVER_MIN)%)" ; \
		awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { exit !(t+0 < m+0) }' \
			&& { echo "coverage below minimum"; exit 1; } || exit 0

.PHONY: cover-html
cover-html: cover
	go tool cover -html=$(COVER_PROFILE)

.PHONY: lint
lint:
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...
	staticcheck ./...

.PHONY: clean
clean: samba-down
	rm -f $(COVER_PROFILE)
