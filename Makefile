.PHONY: build test test-race lint vet fuzz check clean

build:
	go build -o bin/security-gate ./cmd/security-gate

test:
	go test -cover ./...

test-race:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

fuzz:
	@for pkg in $$(go list ./internal/ingest/...); do \
		echo "Fuzzing $$pkg..."; \
		go test -fuzz=Fuzz -fuzztime=30s $$pkg || exit 1; \
	done

check: vet lint test-race
	@echo "All checks passed"

clean:
	rm -rf bin/ reports/
