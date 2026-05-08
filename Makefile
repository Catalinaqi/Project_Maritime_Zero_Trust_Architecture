# ============================================================================
# Makefile - Maritime Zero Trust Architecture
# Common commands for development, testing, and deployment
# ============================================================================

.PHONY: help
help: ## Show this help message
	@echo "Maritime ZTA - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ============================================================================
# SETUP & INSTALLATION
# ============================================================================

.PHONY: install
install: ## Install Python dependencies with Poetry
	poetry install --with dev,test

.PHONY: install-prod
install-prod: ## Install production dependencies only
	poetry install --without dev,test

.PHONY: setup
setup: install init-certs ## Complete initial setup (install + certificates)
	@echo "✓ Setup complete"

.PHONY: init-certs
init-certs: ## Generate PKI certificates
	@echo "Generating PKI certificates..."
	poetry run python scripts/generate_certs.py
	@echo "✓ Certificates generated"

# ============================================================================
# CODE QUALITY
# ============================================================================

.PHONY: format
format: ## Format code with black and isort
	poetry run black scripts/ tests/
	poetry run isort scripts/ tests/
	@echo "✓ Code formatted"

.PHONY: lint
lint: ## Run linters (ruff, mypy)
	poetry run ruff check scripts/ tests/
	poetry run mypy scripts/ tests/
	@echo "✓ Linting complete"

.PHONY: security-check
security-check: ## Run security checks (bandit, safety)
	poetry run bandit -r scripts/
	poetry run safety check
	@echo "✓ Security check complete"

.PHONY: check-all
check-all: format lint security-check ## Run all code quality checks
	@echo "✓ All checks passed"

# ============================================================================
# TESTING
# ============================================================================

.PHONY: test
test: ## Run unit tests
	poetry run pytest tests/ -v

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	poetry run pytest tests/ --cov --cov-report=html --cov-report=term

.PHONY: test-integration
test-integration: ## Run integration tests
	poetry run pytest tests/ -v -m integration

.PHONY: test-security
test-security: ## Run security tests
	poetry run pytest tests/ -v -m security

.PHONY: test-all
test-all: test test-integration test-security ## Run all tests
	@echo "✓ All tests passed"

# ============================================================================
# DOCKER OPERATIONS
# ============================================================================

.PHONY: build
build: ## Build all Docker images
	docker compose build

.PHONY: build-no-cache
build-no-cache: ## Build all Docker images without cache
	docker compose build --no-cache

.PHONY: up
up: ## Start all core services
	docker compose up -d
	@echo "✓ Services started"
	@echo "Run 'make logs' to view logs"

.PHONY: up-full
up-full: ## Start all services including testing clients
	docker compose --profile testing up -d
	@echo "✓ All services started"

.PHONY: down
down: ## Stop all services
	docker compose down
	@echo "✓ Services stopped"

.PHONY: down-volumes
down-volumes: ## Stop services and remove volumes
	docker compose down -v
	@echo "✓ Services stopped and volumes removed"

.PHONY: restart
restart: down up ## Restart all services

.PHONY: logs
logs: ## View logs from all services
	docker compose logs -f

.PHONY: logs-envoy
logs-envoy: ## View Envoy logs
	docker compose logs -f pep_gateway

.PHONY: logs-opa
logs-opa: ## View OPA logs
	docker compose logs -f pdp_engine

.PHONY: logs-mongo
logs-mongo: ## View MongoDB logs
	docker compose logs -f db_primary

.PHONY: logs-splunk
logs-splunk: ## View Splunk logs
	docker compose logs -f siem_central

.PHONY: ps
ps: ## Show running containers
	docker compose ps

.PHONY: stats
stats: ## Show container resource usage
	docker stats

# ============================================================================
# VALIDATION & CONFIGURATION
# ============================================================================

.PHONY: validate-config
validate-config: ## Validate all configuration files
	poetry run python scripts/validate_config.py
	@echo "✓ Configuration validated"

.PHONY: validate-opa
validate-opa: ## Validate OPA policies
	docker run --rm -v $(PWD)/configs/opa/policies:/policies \
		openpolicyagent/opa:latest test /policies

.PHONY: validate-envoy
validate-envoy: ## Validate Envoy configuration
	docker run --rm -v $(PWD)/configs/envoy:/config \
		envoyproxy/envoy:v1.29-latest \
		--mode validate -c /config/envoy.yaml

# ============================================================================
# SECURITY SCANNING
# ============================================================================

.PHONY: scan-images
scan-images: ## Scan Docker images for vulnerabilities
	@echo "Scanning Docker images with Trivy..."
	trivy image --severity HIGH,CRITICAL maritime-zta_pep_gateway || true
	trivy image --severity HIGH,CRITICAL maritime-zta_pdp_engine || true
	trivy image --severity HIGH,CRITICAL maritime-zta_db_primary || true
	@echo "✓ Image scanning complete"

.PHONY: scan-config
scan-config: ## Scan configuration files for issues
	@echo "Scanning configurations..."
	trivy config --severity HIGH,CRITICAL .
	@echo "✓ Config scanning complete"

.PHONY: audit
audit: security-check scan-images scan-config ## Run complete security audit
	@echo "✓ Security audit complete"

# ============================================================================
# DEVELOPMENT
# ============================================================================

.PHONY: shell-envoy
shell-envoy: ## Open shell in Envoy container
	docker exec -it pep_gateway /bin/bash

.PHONY: shell-opa
shell-opa: ## Open shell in OPA container
	docker exec -it pdp_engine /bin/sh

.PHONY: shell-mongo
shell-mongo: ## Open MongoDB shell
	docker exec -it db_primary mongosh

.PHONY: test-mtls
test-mtls: ## Test mTLS connection to Envoy
	curl -v --cacert certs/ca/ca.crt \
		--cert certs/clients/corporate/client.crt \
		--key certs/clients/corporate/client.key \
		https://localhost:8443/health

# ============================================================================
# CLEANUP
# ============================================================================

.PHONY: clean
clean: down ## Clean up containers and temporary files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage coverage.xml
	@echo "✓ Cleanup complete"

.PHONY: clean-all
clean-all: clean down-volumes ## Deep clean (containers, volumes, certs)
	rm -rf certs/ca/ certs/server/ certs/clients/
	@echo "✓ Deep cleanup complete"

# ============================================================================
# DOCUMENTATION
# ============================================================================

.PHONY: docs
docs: ## Build documentation
	poetry run mkdocs build

.PHONY: docs-serve
docs-serve: ## Serve documentation locally
	poetry run mkdocs serve

# ============================================================================
# CI/CD
# ============================================================================

.PHONY: ci
ci: check-all test-coverage validate-config ## Run CI pipeline
	@echo "✓ CI pipeline complete"

.PHONY: pre-commit
pre-commit: format lint test ## Run pre-commit checks
	@echo "✓ Pre-commit checks passed"

# ============================================================================
# DEPLOYMENT
# ============================================================================

.PHONY: deploy-prod
deploy-prod: ## Deploy to production (use with caution)
	@echo "WARNING: Deploying to production"
	@read -p "Are you sure? [y/N]: " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d; \
		echo "✓ Production deployment complete"; \
	else \
		echo "Deployment cancelled"; \
	fi

# ============================================================================
# DEFAULT TARGET
# ============================================================================

.DEFAULT_GOAL := help
