# Makefile for TTP Analyzer

.PHONY: help install install-dev test setup clean run-test lint format docs

# Default target
help:
	@echo "TTP Analyzer - Available Commands:"
	@echo ""
	@echo "Setup Commands:"
	@echo "  install      - Install the package and dependencies"
	@echo "  install-dev  - Install package with development dependencies"
	@echo "  setup        - Create directory structure and sample data"
	@echo "  test-install - Run installation validation tests"
	@echo ""
	@echo "Development Commands:"
	@echo "  test         - Run unit tests"
	@echo "  lint         - Run code linting"
	@echo "  format       - Format code with black"
	@echo "  clean        - Clean up temporary files"
	@echo ""
	@echo "Usage Commands:"
	@echo "  update-data  - Download MITRE ATT&CK framework data"
	@echo "  list-actors  - List available threat actors"
	@echo "  run-test     - Run analysis on test actor"
	@echo "  example      - Create example directory structure"
	@echo ""
	@echo "Documentation:"
	@echo "  docs         - Generate documentation"

# Installation commands
install:
	@echo "Installing TTP Analyzer..."
	pip install -r requirements.txt
	pip install -e .
	@echo "Installation complete!"

install-dev:
	@echo "Installing TTP Analyzer with development dependencies..."
	pip install -r requirements.txt
	pip install -e ".[dev]"
	@echo "Development installation complete!"

# Setup commands
setup:
	@echo "Setting up TTP Analyzer directory structure..."
	mkdir -p groups output data logs
	@echo "Directory structure created!"
	@echo "Run 'make example' to create sample threat actor data"

example:
	@echo "Creating example threat actor data..."
	chmod +x setup_example_groups.sh
	./setup_example_groups.sh
	@echo "Example data created!"

test-install:
	@echo "Running installation validation tests..."
	python test_installation.py

# Development commands
test:
	@echo "Running unit tests..."
	python -m pytest tests/ -v --cov=src --cov-report=html

lint:
	@echo "Running code linting..."
	flake8 src/ tests/ *.py --max-line-length=100
	mypy src/

format:
	@echo "Formatting code..."
	black src/ tests/ *.py --line-length=100
	isort src/ tests/ *.py

clean:
	@echo "Cleaning up temporary files..."
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf build/ dist/ .coverage htmlcov/ .pytest_cache/ .mypy_cache/
	rm -rf output/* logs/*
	@echo "Cleanup complete!"

# Usage commands
update-data:
	@echo "Downloading MITRE ATT&CK framework data..."
	python ttp_analyzer.py --update-attack-data

list-actors:
	@echo "Available threat actors:"
	python ttp_analyzer.py --list-actors

run-test:
	@echo "Running analysis on test actor..."
	python ttp_analyzer.py --actor test_actor --verbose

# Documentation
docs:
	@echo "Generating documentation..."
	sphinx-build -b html docs/ docs/_build/

# Quick start workflow
quickstart: install setup example update-data test-install
	@echo ""
	@echo "🎉 TTP Analyzer setup complete!"
	@echo ""
	@echo "Quick start commands:"
	@echo "  make update-data  - Download ATT&CK data"
	@echo "  make list-actors  - See available threat actors"
	@echo "  make run-test     - Run sample analysis"
	@echo ""
	@echo "Or run manually:"
	@echo "  python ttp_analyzer.py --actor APT1"

# Development workflow
dev-setup: install-dev setup example test-install
	@echo ""
	@echo "🎉 Development environment setup complete!"
	@echo ""
	@echo "Development commands:"
	@echo "  make test    - Run tests"
	@echo "  make lint    - Check code quality"
	@echo "  make format  - Format code"
