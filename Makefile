.PHONY: build test vet lint vuln fmt-check fix-check tidy-check check linux-check integration-deps

# golangci-lint is run at this version, built in isolation rather than
# added to go.mod, as its authors advise.
GOLANGCI_LINT = go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0

build:
	go build -o bin/sftpit ./cmd/sftpit

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	$(GOLANGCI_LINT) run ./...

vuln:
	go tool govulncheck ./...

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

fix-check:
	go fix -diff ./...

tidy-check:
	go mod tidy -diff

check: fmt-check fix-check tidy-check vet lint test

linux-check:
	docker build --tag sftpit-linux-check test/linux
	docker run --rm --volume "$(CURDIR)":/src:ro \
		--volume sftpit-linux-gocache:/home/tester/.cache \
		--volume sftpit-linux-gomod:/home/tester/go \
		sftpit-linux-check make check

integration-deps:
	composer install --working-dir=test/integration/php
