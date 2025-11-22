GOFILES=$(shell find . -name '*.go' -not -path "./vendor/*")

.PHONY: test
test:
	go test ./...

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: vuln
vuln:
	govulncheck ./...

.PHONY: gosec
gosec:
	gosec ./...
