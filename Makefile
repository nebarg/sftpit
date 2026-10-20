.PHONY: build test vet lint vuln fmt-check tidy-check check integration-deps

build:
	go build -o bin/sftpit ./cmd/sftpit

test:
	go test -race ./...

vet:
	go vet ./...

lint:
	go tool staticcheck ./...

vuln:
	go tool govulncheck ./...

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

tidy-check:
	go mod tidy -diff

check: fmt-check tidy-check vet lint test

integration-deps:
	composer install --working-dir=test/integration/phpseclib
