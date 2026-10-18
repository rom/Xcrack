# Xcrack — build & developer tasks.
#
# Requires Go 1.25+ (a go.work ties the three modules together). Compiled
# binaries are written to ./bin. Run `make help` for the target list.

GO      ?= go
BIN     := bin
MODULES := ./xcrypto/... ./xfileformats/... ./xcrack/...
DUR     ?= 20s
LDFLAGS ?=

.DEFAULT_GOAL := build

.PHONY: all build cli server web run-server run-web test race check vet fmt fmt-check fuzz samples tidy clean install help

all: build ## Build everything (alias for build)

build: cli server web ## Build the CLI, the HTTP service and the web GUI into ./bin

cli: ## Build the xcrack CLI -> bin/xcrack
	@mkdir -p $(BIN)
	$(GO) build $(LDFLAGS) -o $(BIN)/xcrack ./xcrack/cmd/xcrack

server: ## Build the xcrackd HTTP service -> bin/xcrackd
	@mkdir -p $(BIN)
	$(GO) build $(LDFLAGS) -o $(BIN)/xcrackd ./xcrack/cmd/xcrackd

web: ## Build the xcrack-web browser GUI -> bin/xcrack-web
	@mkdir -p $(BIN)
	$(GO) build $(LDFLAGS) -o $(BIN)/xcrack-web ./xcrack/cmd/xcrack-web

run-server: server ## Build and run the HTTP service (ADDR overrides :8080)
	$(BIN)/xcrackd -addr $(or $(ADDR),:8080)

run-web: web ## Build and run the web GUI on localhost (ADDR overrides 127.0.0.1:8899)
	$(BIN)/xcrack-web -addr $(or $(ADDR),127.0.0.1:8899)

test: ## Run the full test suite
	$(GO) test $(MODULES)

race: ## Run the test suite under the race detector
	$(GO) test -race $(MODULES)

vet: ## Run go vet across all modules
	$(GO) vet $(MODULES)

fmt: ## Format all Go sources in place
	gofmt -w xcrypto xfileformats xcrack

fmt-check: ## Fail if any Go source is unformatted
	@out=$$(gofmt -l xcrypto xfileformats xcrack); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

fuzz: ## Run every fuzz target briefly (override duration: make fuzz DUR=60s)
	./scripts/fuzz.sh $(DUR)

check: fmt-check vet race ## Run everything CI runs (fmt check, vet, race tests)

samples: ## (Re)generate the demo sample files in ./samples
	bash samples/generate.sh

tidy: ## go mod tidy for every module
	cd xcrypto && $(GO) mod tidy
	cd xfileformats && $(GO) mod tidy
	cd xcrack && $(GO) mod tidy

clean: ## Remove compiled binaries from ./bin
	rm -f $(BIN)/xcrack $(BIN)/xcrackd $(BIN)/xcrack-web

install: ## go install the CLI, service and web GUI into GOBIN
	$(GO) install ./xcrack/cmd/xcrack ./xcrack/cmd/xcrackd ./xcrack/cmd/xcrack-web

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
