# YARA Pipeline Makefile
# Provides simple targets for running the automation pipeline

.PHONY: help pipeline clean status test

# Default target
help:
	@echo "YARA Pipeline Makefile"
	@echo "======================"
	@echo ""
	@echo "Available targets:"
	@echo "  pipeline    - Run the complete pipeline (txt_to_json -> transpile_to_yara)"
	@echo "  clean       - Remove generated output files"
	@echo "  status      - Show current pipeline status"
	@echo "  test        - Run pipeline with clean mode for testing"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make pipeline    # Run the pipeline"
	@echo "  make test        # Clean and run pipeline"
	@echo "  make status      # Check pipeline status"

# Run the complete pipeline
pipeline:
	@echo "🚀 Running YARA pipeline..."
	@python3 scripts/run_pipeline.py

# Clean previous outputs and run pipeline
test:
	@echo "🧹 Cleaning and running YARA pipeline..."
	@python3 scripts/run_pipeline.py --clean

# Show pipeline status
status:
	@echo "📊 Checking pipeline status..."
	@python3 scripts/run_pipeline.py --status

# Clean generated output files
clean:
	@echo "🧹 Cleaning generated files..."
	@rm -f data/signatures.json data/yara_rules.yar
	@echo "✅ Cleaned output files"

# Install dependencies (if requirements.txt exists)
install:
	@if [ -f requirements.txt ]; then \
		echo "📦 Installing dependencies..."; \
		pip3 install -r requirements.txt; \
		echo "✅ Dependencies installed"; \
	else \
		echo "ℹ️  No requirements.txt found"; \
	fi

# Validate the pipeline works
validate: test
	@echo "🔍 Validating pipeline outputs..."
	@if [ -f data/signatures.json ] && [ -f data/yara_rules.yar ]; then \
		echo "✅ Pipeline validation passed"; \
		echo "   - JSON file: data/signatures.json"; \
		echo "   - YARA file: data/yara_rules.yar"; \
	else \
		echo "❌ Pipeline validation failed"; \
		exit 1; \
	fi
