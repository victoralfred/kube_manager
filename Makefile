# Makefile for kube_manager

# Variables
APP_NAME=kube_manager
MAIN_PACKAGE=./cmd/server
KEYGEN_PACKAGE=./cmd/keygen
API_PACKAGE=./cmd/api
BINARY_DIR=./bin
SERVER_BINARY=$(BINARY_DIR)/server
KEYGEN_BINARY=$(BINARY_DIR)/keygen
API_BINARY=$(BINARY_DIR)/api
MIGRATION_DIR=./pkg/migrations/files
GO=go
GOFLAGS=-v
LDFLAGS=-ldflags "-w -s"
TEST_FLAGS=-v -race -coverprofile=coverage.out -covermode=atomic

# Database connection (override with environment variables)
DB_HOST?=localhost
DB_PORT?=5432
DB_USER?=postgres
DB_PASSWORD?=postgres
DB_NAME?=kube_manager
DB_SSLMODE?=disable
DATABASE_URL=postgres://$(DB_USER):$(DB_PASSWORD)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=$(DB_SSLMODE)

# Colors for output
COLOR_RESET=\033[0m
COLOR_BOLD=\033[1m
COLOR_GREEN=\033[32m
COLOR_YELLOW=\033[33m
COLOR_BLUE=\033[34m

.PHONY: help
help: ## Show this help message
	@echo "$(COLOR_BOLD)$(APP_NAME) - Available targets:$(COLOR_RESET)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_BLUE)%-20s$(COLOR_RESET) %s\n", $$1, $$2}'
	@echo ""

.PHONY: all
all: clean deps fmt lint test build ## Run all: clean, deps, fmt, lint, test, build

# Build targets
.PHONY: build
build: build-server build-keygen ## Build all binaries

.PHONY: build-server
build-server: ## Build the server binary
	@echo "$(COLOR_GREEN)Building server...$(COLOR_RESET)"
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(SERVER_BINARY) $(MAIN_PACKAGE)
	@echo "$(COLOR_GREEN)Server built: $(SERVER_BINARY)$(COLOR_RESET)"

.PHONY: build-keygen
build-keygen: ## Build the keygen binary
	@echo "$(COLOR_GREEN)Building keygen...$(COLOR_RESET)"
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(KEYGEN_BINARY) $(KEYGEN_PACKAGE)
	@echo "$(COLOR_GREEN)Keygen built: $(KEYGEN_BINARY)$(COLOR_RESET)"

.PHONY: build-api
build-api: ## Build the api binary
	@echo "$(COLOR_GREEN)Building api...$(COLOR_RESET)"
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(API_BINARY) $(API_PACKAGE)
	@echo "$(COLOR_GREEN)API built: $(API_BINARY)$(COLOR_RESET)"

.PHONY: build-dev
build-dev: ## Build server without optimization (for debugging)
	@echo "$(COLOR_YELLOW)Building server (dev mode)...$(COLOR_RESET)"
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -o $(SERVER_BINARY) $(MAIN_PACKAGE)
	@echo "$(COLOR_YELLOW)Server built (dev mode): $(SERVER_BINARY)$(COLOR_RESET)"

# Run targets
.PHONY: run
run: build-dev ## Build and run the server
	@echo "$(COLOR_BLUE)Starting server...$(COLOR_RESET)"
	$(SERVER_BINARY)

.PHONY: run-direct
run-direct: ## Run the server directly without building binary
	@echo "$(COLOR_BLUE)Running server directly...$(COLOR_RESET)"
	$(GO) run $(MAIN_PACKAGE)

# Test targets
.PHONY: test
test: ## Run tests
	@echo "$(COLOR_BLUE)Running tests...$(COLOR_RESET)"
	$(GO) test $(TEST_FLAGS) ./...

.PHONY: test-unit
test-unit: ## Run unit tests only
	@echo "$(COLOR_BLUE)Running unit tests...$(COLOR_RESET)"
	$(GO) test -v -short ./...

.PHONY: test-integration
test-integration: ## Run integration tests only
	@echo "$(COLOR_BLUE)Running integration tests...$(COLOR_RESET)"
	$(GO) test -v -run Integration ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@echo "$(COLOR_BLUE)Running tests with coverage...$(COLOR_RESET)"
	$(GO) test $(TEST_FLAGS) ./...
	@echo "$(COLOR_GREEN)Coverage report generated: coverage.out$(COLOR_RESET)"
	@echo "$(COLOR_BLUE)Coverage summary:$(COLOR_RESET)"
	@$(GO) tool cover -func=coverage.out | tail -1

.PHONY: test-coverage-html
test-coverage-html: test-coverage ## Generate HTML coverage report
	@echo "$(COLOR_BLUE)Generating HTML coverage report...$(COLOR_RESET)"
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "$(COLOR_GREEN)HTML coverage report: coverage.html$(COLOR_RESET)"

.PHONY: test-rbac
test-rbac: ## Run RBAC tests only
	@echo "$(COLOR_BLUE)Running RBAC tests...$(COLOR_RESET)"
	$(GO) test -v -run TestRBAC ./internal/rbac/...

.PHONY: benchmark
benchmark: ## Run benchmarks
	@echo "$(COLOR_BLUE)Running benchmarks...$(COLOR_RESET)"
	$(GO) test -bench=. -benchmem ./...

# Database migration targets
# Note: Migrations are automatically run at application startup
# These commands are for manual migration management only

.PHONY: migrate-create
migrate-create: ## Create new migration file (usage: make migrate-create NAME=create_users_table)
	@echo "$(COLOR_BLUE)Creating migration: $(NAME)...$(COLOR_RESET)"
	@if [ -z "$(NAME)" ]; then \
		echo "$(COLOR_YELLOW)Error: NAME is required. Usage: make migrate-create NAME=your_migration_name$(COLOR_RESET)"; \
		exit 1; \
	fi
	@NEXT_VERSION=$$(ls -1 $(MIGRATION_DIR) | grep -E '^[0-9]+_' | sed 's/^0*//' | sed 's/_.*//' | sort -n | tail -1 | awk '{print $$1+1}'); \
	if [ -z "$$NEXT_VERSION" ]; then NEXT_VERSION=1; fi; \
	PADDED_VERSION=$$(printf "%03d" $$NEXT_VERSION); \
	UP_FILE=$(MIGRATION_DIR)/$${PADDED_VERSION}_$(NAME).up.sql; \
	DOWN_FILE=$(MIGRATION_DIR)/$${PADDED_VERSION}_$(NAME).down.sql; \
	echo "-- Migration: $(NAME)" > $$UP_FILE; \
	echo "-- Created: $$(date)" >> $$UP_FILE; \
	echo "" >> $$UP_FILE; \
	echo "-- Add your up migration SQL here" >> $$UP_FILE; \
	echo "" >> $$UP_FILE; \
	echo "-- Migration: $(NAME)" > $$DOWN_FILE; \
	echo "-- Created: $$(date)" >> $$DOWN_FILE; \
	echo "" >> $$DOWN_FILE; \
	echo "-- Add your down migration SQL here" >> $$DOWN_FILE; \
	echo "" >> $$DOWN_FILE; \
	echo "$(COLOR_GREEN)Migration files created:$(COLOR_RESET)"; \
	echo "  Up:   $$UP_FILE"; \
	echo "  Down: $$DOWN_FILE"

.PHONY: migrate-status
migrate-status: ## Show migration status from database
	@echo "$(COLOR_BLUE)Querying migration status from database...$(COLOR_RESET)"
	@psql "$(DATABASE_URL)" -c "SELECT version, name, applied_at FROM schema_migrations ORDER BY version;" 2>/dev/null || echo "$(COLOR_YELLOW)Could not connect to database or schema_migrations table doesn't exist yet$(COLOR_RESET)"

.PHONY: migrate-list
migrate-list: ## List all migration files
	@echo "$(COLOR_BLUE)Available migration files:$(COLOR_RESET)"
	@ls -1 $(MIGRATION_DIR)/*.sql 2>/dev/null | sed 's/.*\//  /' || echo "  No migration files found"

# Code quality targets
.PHONY: fmt
fmt: ## Format code
	@echo "$(COLOR_BLUE)Formatting code...$(COLOR_RESET)"
	$(GO) fmt ./...
	@echo "$(COLOR_GREEN)Code formatted$(COLOR_RESET)"

.PHONY: fmt-check
fmt-check: ## Check if code is formatted
	@echo "$(COLOR_BLUE)Checking code formatting...$(COLOR_RESET)"
	@test -z "$$(gofmt -l .)" || (echo "$(COLOR_YELLOW)Code not formatted. Run 'make fmt'$(COLOR_RESET)" && exit 1)

.PHONY: lint
lint: ## Run linter (requires golangci-lint)
	@echo "$(COLOR_BLUE)Running linter...$(COLOR_RESET)"
	@which golangci-lint > /dev/null || (echo "$(COLOR_YELLOW)golangci-lint not installed. Install: https://golangci-lint.run/usage/install/$(COLOR_RESET)" && exit 1)
	golangci-lint run ./...

.PHONY: vet
vet: ## Run go vet
	@echo "$(COLOR_BLUE)Running go vet...$(COLOR_RESET)"
	$(GO) vet ./...

# Dependency targets
.PHONY: deps
deps: ## Download dependencies
	@echo "$(COLOR_BLUE)Downloading dependencies...$(COLOR_RESET)"
	$(GO) mod download
	@echo "$(COLOR_GREEN)Dependencies downloaded$(COLOR_RESET)"

.PHONY: deps-tidy
deps-tidy: ## Tidy dependencies
	@echo "$(COLOR_BLUE)Tidying dependencies...$(COLOR_RESET)"
	$(GO) mod tidy
	@echo "$(COLOR_GREEN)Dependencies tidied$(COLOR_RESET)"

.PHONY: deps-verify
deps-verify: ## Verify dependencies
	@echo "$(COLOR_BLUE)Verifying dependencies...$(COLOR_RESET)"
	$(GO) mod verify

.PHONY: deps-update
deps-update: ## Update dependencies
	@echo "$(COLOR_BLUE)Updating dependencies...$(COLOR_RESET)"
	$(GO) get -u ./...
	$(GO) mod tidy
	@echo "$(COLOR_GREEN)Dependencies updated$(COLOR_RESET)"

# Clean targets
.PHONY: clean
clean: ## Remove build artifacts
	@echo "$(COLOR_YELLOW)Cleaning build artifacts...$(COLOR_RESET)"
	@rm -rf $(BINARY_DIR)
	@rm -f coverage.out coverage.html
	@rm -f *.test
	@rm -f server keygen
	@rm -f rbac.test
	@echo "$(COLOR_GREEN)Clean complete$(COLOR_RESET)"

.PHONY: clean-all
clean-all: clean ## Remove all generated files including vendor
	@echo "$(COLOR_YELLOW)Removing vendor directory...$(COLOR_RESET)"
	@rm -rf vendor/
	@echo "$(COLOR_GREEN)All generated files removed$(COLOR_RESET)"

# Docker targets (if needed in future)
.PHONY: docker-build
docker-build: ## Build Docker image
	@echo "$(COLOR_BLUE)Building Docker image...$(COLOR_RESET)"
	docker build -t $(APP_NAME):latest .

.PHONY: docker-run
docker-run: ## Run Docker container
	@echo "$(COLOR_BLUE)Running Docker container...$(COLOR_RESET)"
	docker run -p 8080:8080 $(APP_NAME):latest

# Install targets
.PHONY: install
install: build ## Install binaries to $GOPATH/bin
	@echo "$(COLOR_BLUE)Installing binaries...$(COLOR_RESET)"
	$(GO) install $(MAIN_PACKAGE)
	$(GO) install $(KEYGEN_PACKAGE)
	@echo "$(COLOR_GREEN)Binaries installed to $$GOPATH/bin$(COLOR_RESET)"

# Development helpers
.PHONY: watch
watch: ## Watch for changes and rebuild (requires entr)
	@echo "$(COLOR_BLUE)Watching for changes...$(COLOR_RESET)"
	@which entr > /dev/null || (echo "$(COLOR_YELLOW)entr not installed. Install: apt-get install entr$(COLOR_RESET)" && exit 1)
	@find . -name '*.go' | entr -r make run-direct

.PHONY: dev
dev: run ## Run development server (migrations run automatically at startup)

# CI/CD targets
.PHONY: ci
ci: deps fmt-check vet lint test ## Run CI pipeline locally

.PHONY: pre-commit
pre-commit: fmt vet test ## Run pre-commit checks

# Version info
.PHONY: version
version: ## Show Go version
	@$(GO) version

# Tool installation helpers
.PHONY: install-tools
install-tools: ## Install development tools
	@echo "$(COLOR_BLUE)Installing development tools...$(COLOR_RESET)"
	@echo "$(COLOR_YELLOW)Installing golangci-lint...$(COLOR_RESET)"
	@which golangci-lint > /dev/null || curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin
	@echo "$(COLOR_YELLOW)Installing migrate...$(COLOR_RESET)"
	@which migrate > /dev/null || go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
	@echo "$(COLOR_GREEN)Development tools installed$(COLOR_RESET)"

.PHONY: info
info: ## Show project information
	@echo "$(COLOR_BOLD)Project Information:$(COLOR_RESET)"
	@echo "  App Name:       $(APP_NAME)"
	@echo "  Go Version:     $$($(GO) version)"
	@echo "  Server Binary:  $(SERVER_BINARY)"
	@echo "  Keygen Binary:  $(KEYGEN_BINARY)"
	@echo "  Migrations:     $(MIGRATION_DIR)"
	@echo "  Database URL:   postgres://$(DB_USER):***@$(DB_HOST):$(DB_PORT)/$(DB_NAME)"
	@echo ""

# Default target
.DEFAULT_GOAL := help
