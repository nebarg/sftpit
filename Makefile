.PHONY: build test vet lint vuln fmt-check check

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

check: fmt-check vet lint test
