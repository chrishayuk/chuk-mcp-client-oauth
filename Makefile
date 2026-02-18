.PHONY: clean clean-pyc clean-build clean-test clean-all test run build publish help install dev-install version bump-patch bump-minor bump-major release release-patch release-minor release-major

# Default target
help:
	@echo "Available targets:"
	@echo "  clean          - Remove Python bytecode and basic artifacts"
	@echo "  clean-all      - Deep clean everything (pyc, build, test, cache)"
	@echo "  clean-pyc      - Remove Python bytecode files"
	@echo "  clean-build    - Remove build artifacts"
	@echo "  clean-test     - Remove test artifacts"
	@echo "  install        - Install package in current environment"
	@echo "  dev-install    - Install package in development mode with all extras"
	@echo "  test           - Run tests"
	@echo "  test-cov       - Run tests with coverage report"
	@echo "  coverage-report - Show current coverage report"
	@echo "  lint           - Run code linters"
	@echo "  format         - Auto-format code"
	@echo "  typecheck      - Run type checking"
	@echo "  security       - Run security checks with bandit"
	@echo "  check          - Run all checks (format, lint, typecheck, security, test)"
	@echo "  build          - Build the project"
	@echo "  publish        - Build and publish to PyPI"
	@echo "  publish-test   - Build and publish to Test PyPI"
	@echo "  version        - Show current version"
	@echo "  bump-patch     - Bump patch version (0.0.X)"
	@echo "  bump-minor     - Bump minor version (0.X.0)"
	@echo "  bump-major     - Bump major version (X.0.0)"
	@echo "  release-patch  - Bump patch, commit, tag, and push (triggers release)"
	@echo "  release-minor  - Bump minor, commit, tag, and push (triggers release)"
	@echo "  release-major  - Bump major, commit, tag, and push (triggers release)"

# Basic clean - Python bytecode and common artifacts
clean: clean-pyc clean-build
	@echo "Basic clean complete."

# Remove Python bytecode files and __pycache__ directories
clean-pyc:
	@echo "Cleaning Python bytecode files..."
	@find . -type f -name '*.pyc' -delete 2>/dev/null || true
	@find . -type f -name '*.pyo' -delete 2>/dev/null || true
	@find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true

# Remove build artifacts
clean-build:
	@echo "Cleaning build artifacts..."
	@rm -rf build/ dist/ *.egg-info 2>/dev/null || true
	@rm -rf .eggs/ 2>/dev/null || true
	@find . -name '*.egg' -exec rm -f {} + 2>/dev/null || true

# Remove test artifacts
clean-test:
	@echo "Cleaning test artifacts..."
	@rm -rf .pytest_cache/ 2>/dev/null || true
	@rm -rf .coverage 2>/dev/null || true
	@rm -rf htmlcov/ 2>/dev/null || true
	@rm -rf .tox/ 2>/dev/null || true
	@rm -rf .cache/ 2>/dev/null || true
	@find . -name '.coverage.*' -delete 2>/dev/null || true

# Deep clean - everything
clean-all: clean-pyc clean-build clean-test
	@echo "Deep cleaning..."
	@rm -rf .mypy_cache/ 2>/dev/null || true
	@rm -rf .ruff_cache/ 2>/dev/null || true
	@rm -rf .venv/ 2>/dev/null || true
	@rm -rf node_modules/ 2>/dev/null || true
	@find . -name '.DS_Store' -delete 2>/dev/null || true
	@find . -name 'Thumbs.db' -delete 2>/dev/null || true
	@find . -name '*.log' -delete 2>/dev/null || true
	@find . -name '*.tmp' -delete 2>/dev/null || true
	@find . -name '*~' -delete 2>/dev/null || true
	@echo "Deep clean complete."

# Install package
install:
	@echo "Installing package..."
	@if command -v uv >/dev/null 2>&1; then \
		uv pip install .; \
	else \
		pip install .; \
	fi

# Install package in development mode
dev-install:
	@echo "Installing package in development mode..."
	@if command -v uv >/dev/null 2>&1; then \
		uv pip install -e ".[dev,all]"; \
	else \
		pip install -e ".[dev,all]"; \
	fi

# Run tests
test:
	@echo "Running tests..."
	@if command -v uv >/dev/null 2>&1; then \
		uv sync --all-extras --dev --quiet && uv run python -m pytest; \
	elif command -v pytest >/dev/null 2>&1; then \
		pytest; \
	else \
		python -m pytest; \
	fi

# Show current coverage report
coverage-report:
	@echo "Coverage Report:"
	@echo "================"
	@if command -v uv >/dev/null 2>&1; then \
		uv run coverage report --omit="tests/*" || echo "No coverage data found. Run 'make test-cov' first."; \
	else \
		coverage report --omit="tests/*" || echo "No coverage data found. Run 'make test-cov' first."; \
	fi

# Run tests with coverage
test-cov:
	@echo "Running tests with coverage..."
	@if command -v uv >/dev/null 2>&1; then \
		uv sync --all-extras --dev --quiet && uv run python -m pytest --cov=src/chuk_mcp_client_oauth --cov-report=html --cov-report=term --cov-report=term-missing:skip-covered; \
		exit_code=$$?; \
		echo ""; \
		echo "=========================="; \
		echo "Coverage Summary:"; \
		echo "=========================="; \
		uv run python -m coverage report --omit="tests/*" | tail -5; \
		echo ""; \
		echo "HTML coverage report saved to: htmlcov/index.html"; \
		exit $$exit_code; \
	else \
		pytest --cov=src/chuk_mcp_client_oauth --cov-report=html --cov-report=term --cov-report=term-missing:skip-covered; \
		exit_code=$$?; \
		echo ""; \
		echo "=========================="; \
		echo "Coverage Summary:"; \
		echo "=========================="; \
		coverage report --omit="tests/*" | tail -5; \
		echo ""; \
		echo "HTML coverage report saved to: htmlcov/index.html"; \
		exit $$exit_code; \
	fi

# Build the project using the pyproject.toml configuration
build: clean-build
	@echo "Building project..."
	@if command -v uv >/dev/null 2>&1; then \
		uv build; \
	else \
		python3 -m build; \
	fi
	@echo "Build complete. Distributions are in the 'dist' folder."

# Publish the package to PyPI using twine
publish: build
	@echo "Publishing package..."
	@if [ ! -d "dist" ] || [ -z "$$(ls -A dist 2>/dev/null)" ]; then \
		echo "Error: No distribution files found. Run 'make build' first."; \
		exit 1; \
	fi
	@last_build=$$(ls -t dist/*.tar.gz dist/*.whl 2>/dev/null | head -n 2); \
	if [ -z "$$last_build" ]; then \
		echo "Error: No valid distribution files found."; \
		exit 1; \
	fi; \
	echo "Uploading: $$last_build"; \
	twine upload $$last_build
	@echo "Publish complete."

# Publish to test PyPI
publish-test: build
	@echo "Publishing to test PyPI..."
	@last_build=$$(ls -t dist/*.tar.gz dist/*.whl 2>/dev/null | head -n 2); \
	if [ -z "$$last_build" ]; then \
		echo "Error: No valid distribution files found."; \
		exit 1; \
	fi; \
	echo "Uploading to test PyPI: $$last_build"; \
	twine upload --repository testpypi $$last_build

# Check code quality
lint:
	@echo "Running linters..."
	@if command -v uv >/dev/null 2>&1; then \
		uv run ruff check .; \
		uv run ruff format --check .; \
	elif command -v ruff >/dev/null 2>&1; then \
		ruff check .; \
		ruff format --check .; \
	else \
		echo "Ruff not found. Install with: pip install ruff"; \
	fi

# Fix code formatting
format:
	@echo "Formatting code..."
	@if command -v uv >/dev/null 2>&1; then \
		uv run ruff format .; \
		uv run ruff check --fix .; \
	elif command -v ruff >/dev/null 2>&1; then \
		ruff format .; \
		ruff check --fix .; \
	else \
		echo "Ruff not found. Install with: pip install ruff"; \
	fi

# Type checking
typecheck:
	@echo "Running type checker..."
	@if command -v uv >/dev/null 2>&1; then \
		uv run mypy src/chuk_mcp_client_oauth; \
	elif command -v mypy >/dev/null 2>&1; then \
		mypy src/chuk_mcp_client_oauth; \
	else \
		echo "MyPy not found. Install with: pip install mypy"; \
	fi

# Security checks with bandit
security:
	@echo "Running security checks with bandit..."
	@if command -v uv >/dev/null 2>&1; then \
		uv run bandit -r src/chuk_mcp_client_oauth -ll || true; \
	elif command -v bandit >/dev/null 2>&1; then \
		bandit -r src/chuk_mcp_client_oauth -ll || true; \
	else \
		echo "Bandit not found. Install with: pip install bandit"; \
	fi

# Run all checks
check: format lint typecheck security test
	@echo "All checks completed successfully!"

# Show project info
info:
	@echo "Project Information:"
	@echo "==================="
	@if [ -f "pyproject.toml" ]; then \
		echo "pyproject.toml found"; \
		if command -v uv >/dev/null 2>&1; then \
			echo "UV version: $$(uv --version)"; \
		fi; \
		if command -v python >/dev/null 2>&1; then \
			echo "Python version: $$(python --version)"; \
		fi; \
	else \
		echo "No pyproject.toml found"; \
	fi
	@echo "Current directory: $$(pwd)"
	@echo "Git status:"
	@git status --porcelain 2>/dev/null || echo "Not a git repository"

# Version management
version:
	@echo "Current version:"
	@grep '^version = ' pyproject.toml | cut -d'"' -f2

bump-patch:
	@echo "Bumping patch version..."
	@CURRENT=$$(grep '^version = ' pyproject.toml | cut -d'"' -f2); \
	MAJOR=$$(echo $$CURRENT | cut -d'.' -f1); \
	MINOR=$$(echo $$CURRENT | cut -d'.' -f2); \
	PATCH=$$(echo $$CURRENT | cut -d'.' -f3); \
	NEW_PATCH=$$((PATCH + 1)); \
	NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
	echo "$$CURRENT -> $$NEW_VERSION"; \
	sed -i.bak "s/^version = \"$$CURRENT\"/version = \"$$NEW_VERSION\"/" pyproject.toml && rm pyproject.toml.bak; \
	echo "Version bumped to $$NEW_VERSION"; \
	echo "Don't forget to commit and tag: git tag v$$NEW_VERSION"

bump-minor:
	@echo "Bumping minor version..."
	@CURRENT=$$(grep '^version = ' pyproject.toml | cut -d'"' -f2); \
	MAJOR=$$(echo $$CURRENT | cut -d'.' -f1); \
	MINOR=$$(echo $$CURRENT | cut -d'.' -f2); \
	NEW_MINOR=$$((MINOR + 1)); \
	NEW_VERSION="$$MAJOR.$$NEW_MINOR.0"; \
	echo "$$CURRENT -> $$NEW_VERSION"; \
	sed -i.bak "s/^version = \"$$CURRENT\"/version = \"$$NEW_VERSION\"/" pyproject.toml && rm pyproject.toml.bak; \
	echo "Version bumped to $$NEW_VERSION"; \
	echo "Don't forget to commit and tag: git tag v$$NEW_VERSION"

bump-major:
	@echo "Bumping major version..."
	@CURRENT=$$(grep '^version = ' pyproject.toml | cut -d'"' -f2); \
	MAJOR=$$(echo $$CURRENT | cut -d'.' -f1); \
	NEW_MAJOR=$$((MAJOR + 1)); \
	NEW_VERSION="$$NEW_MAJOR.0.0"; \
	echo "$$CURRENT -> $$NEW_VERSION"; \
	sed -i.bak "s/^version = \"$$CURRENT\"/version = \"$$NEW_VERSION\"/" pyproject.toml && rm pyproject.toml.bak; \
	echo "Version bumped to $$NEW_VERSION"; \
	echo "Don't forget to commit and tag: git tag v$$NEW_VERSION"

# Release targets (bump, commit, tag, push)
release-patch: check
	@echo "Creating patch release..."
	@CURRENT=$$(grep '^version = ' pyproject.toml | cut -d'"' -f2); \
	MAJOR=$$(echo $$CURRENT | cut -d'.' -f1); \
	MINOR=$$(echo $$CURRENT | cut -d'.' -f2); \
	PATCH=$$(echo $$CURRENT | cut -d'.' -f3); \
	NEW_PATCH=$$((PATCH + 1)); \
	NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
	echo ""; \
	echo "Release: $$CURRENT -> $$NEW_VERSION"; \
	echo ""; \
	read -p "Continue with release v$$NEW_VERSION? [y/N] " -n 1 -r; \
	echo ""; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		sed -i.bak "s/^version = \"$$CURRENT\"/version = \"$$NEW_VERSION\"/" pyproject.toml && rm pyproject.toml.bak; \
		git add pyproject.toml; \
		git commit -m "Bump version to $$NEW_VERSION"; \
		git tag -a "v$$NEW_VERSION" -m "Release v$$NEW_VERSION"; \
		echo ""; \
		echo "✅ Version bumped to $$NEW_VERSION"; \
		echo "✅ Changes committed"; \
		echo "✅ Tag v$$NEW_VERSION created"; \
		echo ""; \
		echo "Push to trigger release:"; \
		echo "  git push origin main --tags"; \
		echo ""; \
		read -p "Push now? [y/N] " -n 1 -r; \
		echo ""; \
		if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
			git push origin main --tags; \
			echo ""; \
			echo "🚀 Release triggered! Check GitHub Actions:"; \
			echo "   https://github.com/chrishayuk/chuk-mcp-client-oauth/actions"; \
		else \
			echo "Skipped push. Run manually: git push origin main --tags"; \
		fi; \
	else \
		echo "Release cancelled."; \
	fi

release-minor: check
	@echo "Creating minor release..."
	@CURRENT=$$(grep '^version = ' pyproject.toml | cut -d'"' -f2); \
	MAJOR=$$(echo $$CURRENT | cut -d'.' -f1); \
	MINOR=$$(echo $$CURRENT | cut -d'.' -f2); \
	NEW_MINOR=$$((MINOR + 1)); \
	NEW_VERSION="$$MAJOR.$$NEW_MINOR.0"; \
	echo ""; \
	echo "Release: $$CURRENT -> $$NEW_VERSION"; \
	echo ""; \
	read -p "Continue with release v$$NEW_VERSION? [y/N] " -n 1 -r; \
	echo ""; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		sed -i.bak "s/^version = \"$$CURRENT\"/version = \"$$NEW_VERSION\"/" pyproject.toml && rm pyproject.toml.bak; \
		git add pyproject.toml; \
		git commit -m "Bump version to $$NEW_VERSION"; \
		git tag -a "v$$NEW_VERSION" -m "Release v$$NEW_VERSION"; \
		echo ""; \
		echo "✅ Version bumped to $$NEW_VERSION"; \
		echo "✅ Changes committed"; \
		echo "✅ Tag v$$NEW_VERSION created"; \
		echo ""; \
		echo "Push to trigger release:"; \
		echo "  git push origin main --tags"; \
		echo ""; \
		read -p "Push now? [y/N] " -n 1 -r; \
		echo ""; \
		if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
			git push origin main --tags; \
			echo ""; \
			echo "🚀 Release triggered! Check GitHub Actions:"; \
			echo "   https://github.com/chrishayuk/chuk-mcp-client-oauth/actions"; \
		else \
			echo "Skipped push. Run manually: git push origin main --tags"; \
		fi; \
	else \
		echo "Release cancelled."; \
	fi

release-major: check
	@echo "Creating major release..."
	@CURRENT=$$(grep '^version = ' pyproject.toml | cut -d'"' -f2); \
	MAJOR=$$(echo $$CURRENT | cut -d'.' -f1); \
	NEW_MAJOR=$$((MAJOR + 1)); \
	NEW_VERSION="$$NEW_MAJOR.0.0"; \
	echo ""; \
	echo "⚠️  MAJOR RELEASE: $$CURRENT -> $$NEW_VERSION"; \
	echo ""; \
	read -p "Continue with MAJOR release v$$NEW_VERSION? [y/N] " -n 1 -r; \
	echo ""; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		sed -i.bak "s/^version = \"$$CURRENT\"/version = \"$$NEW_VERSION\"/" pyproject.toml && rm pyproject.toml.bak; \
		git add pyproject.toml; \
		git commit -m "Bump version to $$NEW_VERSION"; \
		git tag -a "v$$NEW_VERSION" -m "Release v$$NEW_VERSION"; \
		echo ""; \
		echo "✅ Version bumped to $$NEW_VERSION"; \
		echo "✅ Changes committed"; \
		echo "✅ Tag v$$NEW_VERSION created"; \
		echo ""; \
		echo "Push to trigger release:"; \
		echo "  git push origin main --tags"; \
		echo ""; \
		read -p "Push now? [y/N] " -n 1 -r; \
		echo ""; \
		if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
			git push origin main --tags; \
			echo ""; \
			echo "🚀 Release triggered! Check GitHub Actions:"; \
			echo "   https://github.com/chrishayuk/chuk-mcp-client-oauth/actions"; \
		else \
			echo "Skipped push. Run manually: git push origin main --tags"; \
		fi; \
	else \
		echo "Release cancelled."; \
	fi
