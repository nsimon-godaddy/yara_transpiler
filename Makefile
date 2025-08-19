# YARA Pipeline Makefile with LLM Validation
# Provides simple targets for running the automation pipeline

.PHONY: help pipeline clean status test validate validate-sample

# Default target
help:
	@echo "YARA Pipeline Makefile with LLM Validation"
	@echo "=========================================="
	@echo ""
	@echo "Available targets:"
	@echo "  pipeline        - Run the complete pipeline (txt_to_json -> transpile_to_yara)"
	@echo "  validate        - Run pipeline with LLM validation of all rules"
	@echo "  validate-sample - Run pipeline with LLM validation of 10 random rules"
	@echo "  clean           - Remove generated output files"
	@echo "  status          - Show current pipeline status"
	@echo "  test            - Run pipeline with clean mode for testing"
	@echo "  help            - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make pipeline        # Run the basic pipeline"
	@echo "  make validate        # Run pipeline with full LLM validation"
	@echo "  make validate-sample # Run pipeline with sample validation"
	@echo "  make test            # Clean and run pipeline"
	@echo "  make status          # Check pipeline status"
	@echo ""
	@echo "Note: LLM validation requires JWT and API_URL environment variables"

# Run the complete pipeline
pipeline:
	@echo "🚀 Running YARA pipeline..."
	@python3 scripts/run_pipeline.py

# Run pipeline with LLM validation
validate:
	@echo "🔍 Running YARA pipeline with LLM validation..."
	@python3 scripts/run_pipeline.py --validate

# Run pipeline with sample LLM validation (10 rules)
validate-sample:
	@echo "🎲 Running YARA pipeline with sample LLM validation (10 rules)..."
	@python3 scripts/run_pipeline.py --validate --sample 10

# Clean previous outputs and run pipeline
test:
	@echo "🧹 Cleaning and running YARA pipeline..."
	@python3 scripts/run_pipeline.py --clean

# Clean and run with validation
test-validate:
	@echo "🧹 Cleaning and running YARA pipeline with LLM validation..."
	@python3 scripts/run_pipeline.py --clean --validate

# Show pipeline status
status:
	@echo "📊 Checking pipeline status..."
	@python3 scripts/run_pipeline.py --status

# Clean generated output files
clean:
	@echo "🧹 Cleaning generated files..."
	@rm -f data/signatures.json data/yara_rules.yar
	@rm -f validation_results_*.json
	@rm -f validation.log
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
validate-pipeline: test
	@echo "🔍 Validating pipeline outputs..."
	@if [ -f data/signatures.json ] && [ -f data/yara_rules.yar ]; then \
		echo "✅ Pipeline validation passed"; \
		echo "   - JSON file: data/signatures.json"; \
		echo "   - YARA file: data/yara_rules.yar"; \
	else \
		echo "❌ Pipeline validation failed"; \
		exit 1; \
	fi

# Check environment setup for validation
check-env:
	@echo "🔍 Checking environment setup..."
	@if [ -n "$$JWT" ] && [ -n "$$API_URL" ]; then \
		echo "✅ Environment variables found"; \
		echo "   - JWT: $${JWT:0:20}..."; \
		echo "   - API_URL: $$API_URL"; \
	else \
		echo "❌ Missing environment variables"; \
		echo "   Set JWT and API_URL in your environment or .env file"; \
		exit 1; \
	fi

# Run validation only (requires existing YARA file)
validate-only:
	@echo "🔍 Running LLM validation on existing YARA rules..."
	@python3 scripts/llm_validation.py data/yara_rules.yar --json-file data/signatures.json
