WORKDIR := $(shell pwd)
MODULES := $(if $(wildcard go.work),$(shell awk '/^\t\.?\/?.+$$/ {sub(/^\.\//, "", $$1); print $$1}' go.work), .)
LINT_VERSION := v2.7.2

run: tidy lint test

bench:
	@echo "\033[33mRun \033[32mgo test\033[0m:"
	@(for mod in $(MODULES); do \
		if [ "$$mod" != "." ]; then \
			mod="./$$mod"; \
		fi; \
		cd $(WORKDIR); \
		cd $$mod; \
		go test -v ./... -bench=. ; \
	done)

test:
	@echo "\033[33mRun \033[32mgo test\033[0m:"
	@(for mod in $(MODULES); do \
		if [ "$$mod" != "." ]; then \
			mod="./$$mod"; \
		fi; \
		cd $(WORKDIR); \
		cd $$mod; \
		go test ./...; \
	done)

tidy:
	@echo "\033[33mRun \033[32mgo mod tidy\033[0m:"
	@(for mod in $(MODULES); do \
		if [ "$$mod" != "." ]; then \
			mod="./$$mod"; \
		fi; \
		echo "$$mod"; \
		cd $(WORKDIR); \
		cd $$mod; \
		go mod tidy; \
	done)

lint:
	@echo "\033[33mRun \033[32mgo-lint\033[0m: $(LINT_VERSION)"
	@docker run --rm \
		-v $(shell pwd):/app \
		-v $(HOME)/.netrc:/root/.netrc \
		-v $(HOME)/.cache/golangci-lint:/root/.cache \
		-w /app \
		golangci/golangci-lint:$(LINT_VERSION) \
		golangci-lint run --config .golangci.yml