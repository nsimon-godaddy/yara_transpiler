# YARA Pipeline Automation with LLM Validation

This automation pipeline runs both the `txt_to_json` and `transpile_to_yara` scripts in sequence, converting signature patterns from text format to JSON and then to YARA rules. **NEW**: Now includes optional LLM validation using the Gocaas API for quality assurance.

## Overview

The pipeline consists of three main steps:

1. **Text to JSON Conversion** (`txt_to_json.py`)
   - Converts `data/signature_patterns.txt` to `data/signatures.json`
   - Parses signature blocks and cleanup constants
   - Handles duplicate signature detection

2. **JSON to YARA Conversion** (`transpile_to_yara.py`)
   - Converts `data/signatures.json` to `data/yara_rules.yar`
   - Generates YARA rules from signature data
   - Sanitizes rule names and escapes strings

3. **LLM Validation** (`llm_validation.py`) ⭐ **NEW**
   - Uses Gocaas API with Claude 3.5 Haiku
   - Validates YARA rules for correctness and effectiveness
   - Provides detailed feedback and recommendations
   - Generates comprehensive validation reports

## Files

- `scripts/run_pipeline.py` - Main Python pipeline script with validation
- `scripts/llm_validation.py` - LLM validation layer using Gocaas API
- `run_pipeline.sh` - Shell script wrapper with validation options
- `Makefile` - Make targets including validation operations
- `PIPELINE_README.md` - This documentation file

## Prerequisites

### For Basic Pipeline
- Python 3.6+
- Access to the `scripts/` and `data/` directories
- Input file: `data/signature_patterns.txt`

### For LLM Validation ⭐
- **JWT token** from Gocaas
- **API URL** for Gocaas API
- Environment variables set in `.env` file:
  ```bash
  JWT=your_jwt_token_here
  API_URL=https://api.gocaas.com/v1/chat/completions
  ```

## Usage

### Option 1: Shell Script (Recommended)

#### Basic Pipeline
```bash
# Run the complete pipeline
./run_pipeline.sh

# Clean previous outputs and run
./run_pipeline.sh --clean

# Check pipeline status
./run_pipeline.sh --status
```

#### With LLM Validation ⭐
```bash
# Run pipeline with full LLM validation
./run_pipeline.sh --validate

# Clean, run, and validate
./run_pipeline.sh --clean --validate

# Validate only first 10 rules (for testing)
./run_pipeline.sh --validate --max-rules 10

# Validate random sample of 5 rules
./run_pipeline.sh --validate --sample 5

# Show help
./run_pipeline.sh --help
```

### Option 2: Python Directly

#### Basic Pipeline
```bash
# Run the complete pipeline
python3 scripts/run_pipeline.py

# Clean previous outputs and run
python3 scripts/run_pipeline.py --clean

# Check pipeline status
python3 scripts/run_pipeline.py --status
```

#### With LLM Validation ⭐
```bash
# Run pipeline with LLM validation
python3 scripts/run_pipeline.py --validate

# Clean, run, and validate
python3 scripts/run_pipeline.py --clean --validate

# Validate with custom limits
python3 scripts/run_pipeline.py --validate --max-rules 20
python3 scripts/run_pipeline.py --validate --sample 15

# Use custom directories
python3 scripts/run_pipeline.py --data-dir custom_data --scripts-dir custom_scripts --validate
```

### Option 3: Make Commands

#### Basic Pipeline
```bash
make pipeline    # Run the pipeline
make test        # Clean and run pipeline
make status      # Check pipeline status
```

#### With LLM Validation ⭐
```bash
make validate        # Run pipeline with full validation
make validate-sample # Run pipeline with sample validation (10 rules)
make test-validate   # Clean, run, and validate
make validate-only   # Run validation on existing YARA file
make check-env       # Check environment variables
```

## Pipeline Flow

### Basic Pipeline
```
data/signature_patterns.txt (58KB)
           ↓
    txt_to_json.py
           ↓
    data/signatures.json (82KB)
           ↓
   transpile_to_yara.py
           ↓
    data/yara_rules.yar (74KB)
```

### With LLM Validation ⭐
```
data/signature_patterns.txt (58KB)
           ↓
    txt_to_json.py
           ↓
    data/signatures.json (82KB)
           ↓
   transpile_to_yara.py
           ↓
    data/yara_rules.yar (74KB)
           ↓
   llm_validation.py (Gocaas API)
           ↓
validation_results_*.json + validation.log
```

## LLM Validation Features ⭐

### What Gets Validated
- **Syntax Correctness** - YARA rule syntax validation
- **Pattern Effectiveness** - Threat detection capability
- **Performance Considerations** - Optimization opportunities
- **False Positive Risk** - Risk assessment (LOW/MEDIUM/HIGH)
- **Security Implications** - Threat coverage analysis
- **Best Practices** - YARA rule standards compliance
- **Recommendations** - Specific improvement suggestions
- **Overall Score** - 1-10 rating system

### Validation Options
- **Full Validation** - All generated rules
- **Limited Validation** - Maximum N rules
- **Sample Validation** - Random N rules
- **Context-Aware** - Uses original signature data for better analysis

### Output Files
- **`validation_results_*.json`** - Structured validation results
- **`validation.log`** - Detailed validation logs
- **Console Output** - Real-time validation progress

## Features

- **Automatic Validation**: Checks input files and validates outputs
- **LLM Quality Assurance**: AI-powered rule validation using Claude 3.5 Haiku
- **Error Handling**: Comprehensive error reporting with detailed logs
- **Logging**: Both console and file logging (`pipeline.log`, `validation.log`)
- **Clean Mode**: Option to remove previous outputs before running
- **Status Checking**: Verify pipeline file status without running
- **Flexible Paths**: Customizable data and scripts directories
- **Progress Tracking**: Real-time progress updates with emojis
- **Validation Control**: Configurable validation scope and limits

## Output Files

### `data/signatures.json`
Contains parsed signature data in structured JSON format:
```json
{
  "cleanup_constants": [
    {"name": "CLEAR_COLUMN", "value": "~^.*$~s"},
    {"name": "script_src", "value": "..."}
  ],
  "signatures": [
    {
      "name": "backdoor.curl.002",
      "cleanup_pattern": "...",
      "triggers": ["..."],
      "full_chain": ["..."]
    }
  ]
}
```

### `data/yara_rules.yar`
Contains generated YARA rules:
```yara
rule backdoor_curl_002
{
    meta:
        description = "Converted from JSON signature backdoor.curl.002"

    strings:
        $fullchain0 = "AfterFilterCallbac" ascii
        $fullchain1 = "curl${IFS%??}-" ascii

    condition:
        all of ($fullchain*)
}
```

### `validation_results_*.json` ⭐
Contains LLM validation results:
```json
{
  "validation_summary": {
    "total_rules": 10,
    "successfully_validated": 10,
    "validation_errors": 0,
    "success_rate": 100.0
  },
  "rule_results": [
    {
      "rule_name": "backdoor_curl_002",
      "status": "validated",
      "validation_content": "Detailed LLM analysis...",
      "timestamp": "2024-01-15T10:30:00"
    }
  ]
}
```

## Error Handling

The pipeline includes comprehensive error handling:

- **Prerequisites Check**: Verifies all required files exist
- **Environment Validation**: Checks for LLM validation requirements
- **Subprocess Monitoring**: Captures and reports script output
- **File Validation**: Ensures output files are created and valid
- **Graceful Failure**: Stops execution on first error with detailed reporting
- **Validation Resilience**: Continues pipeline even if validation fails

## Logging

Logs are written to both:
- **Console**: Real-time progress updates
- **File**: `pipeline.log` for pipeline operations, `validation.log` for validation

Log levels include:
- 🔍 Info: Pipeline progress and status
- ✅ Success: Completed steps
- ❌ Error: Failed operations
- ⚠️ Warning: Non-critical issues
- 🔍 Validation: LLM validation progress

## Environment Setup for LLM Validation

### 1. Create `.env` file
```bash
# .env file in project root
JWT=your_gocaas_jwt_token_here
API_URL=https://api.gocaas.com/v1/chat/completions
```

### 2. Verify Setup
```bash
# Check environment variables
make check-env

# Or manually
echo "JWT: $JWT"
echo "API_URL: $API_URL"
```

### 3. Test Validation
```bash
# Run with sample validation first
./run_pipeline.sh --validate --sample 3

# Check results
ls -la validation_results_*.json
cat validation.log
```

## Requirements

- Python 3.6+
- `requests` library for API calls
- `python-dotenv` for environment variable loading
- Access to the `scripts/` and `data/` directories
- Input file: `data/signature_patterns.txt`
- **For validation**: Gocaas API access with JWT token

## Troubleshooting

### Common Issues

1. **Permission Denied**: Make sure `run_pipeline.sh` is executable
   ```bash
   chmod +x run_pipeline.sh
   ```

2. **File Not Found**: Ensure you're running from the project root directory
   ```bash
   pwd  # Should show /path/to/yara
   ls scripts/run_pipeline.py  # Should exist
   ```

3. **Python Not Found**: Ensure Python 3 is installed and in PATH
   ```bash
   python3 --version
   ```

4. **Missing Dependencies**: Check that all required Python packages are installed
   ```bash
   pip3 install -r requirements.txt
   ```

5. **Validation Fails**: Check environment variables
   ```bash
   make check-env
   # Or manually check
   echo "JWT: $JWT"
   echo "API_URL: $API_URL"
   ```

### Debug Mode

For detailed debugging, check the log files:
```bash
tail -f pipeline.log      # Pipeline operations
tail -f validation.log    # LLM validation details
```

### Validation Issues

- **API Errors**: Check JWT token validity and API URL
- **Rate Limiting**: Use `--max-rules` or `--sample` for large rule sets
- **Timeout Issues**: Increase timeout in validation script if needed

## Examples

### Basic Pipeline Run
```bash
$ ./run_pipeline.sh
🚀 YARA Pipeline Runner with LLM Validation
==================================================
📁 Current directory: /Users/nsimon/code/yara
🔧 Command: python3 scripts/run_pipeline.py

Starting pipeline execution...

2024-01-15 10:30:00 - INFO - 🚀 Starting YARA pipeline...
2024-01-15 10:30:00 - INFO - 📁 Working directory: /Users/nsimon/code/yara
2024-01-15 10:30:00 - INFO - 🔍 Checking prerequisites...
2024-01-15 10:30:00 - INFO - ✅ All prerequisites met
2024-01-15 10:30:00 - INFO - 🔄 Step 1: Converting signature patterns to JSON...
2024-01-15 10:30:01 - INFO - ✅ JSON conversion completed successfully
2024-01-15 10:30:01 - INFO - 🔄 Step 2: Converting JSON to YARA rules...
2024-01-15 10:30:01 - INFO - ✅ YARA conversion completed successfully
2024-01-15 10:30:01 - INFO - 🔍 Validating output files...
2024-01-15 10:30:01 - INFO - 📊 JSON validation: 237 signatures, 4 constants
2024-01-15 10:30:01 - INFO - 📊 YARA validation: 237 rules generated
2024-01-15 10:30:01 - INFO - ✅ Output validation completed
2024-01-15 10:30:01 - INFO - 🎉 Pipeline completed successfully!

✅ Pipeline completed successfully!
```

### Pipeline with LLM Validation
```bash
$ ./run_pipeline.sh --validate --sample 5
🚀 YARA Pipeline Runner with LLM Validation
==================================================
📁 Current directory: /Users/nsimon/code/yara
🔧 Command: python3 scripts/run_pipeline.py --validate --sample 5
✅ Environment variables found for LLM validation

Starting pipeline execution...

2024-01-15 10:30:00 - INFO - 🚀 Starting YARA pipeline...
2024-01-15 10:30:00 - INFO - 📁 Working directory: /Users/nsimon/code/yara
2024-01-15 10:30:00 - INFO - 🔍 Checking prerequisites...
2024-01-15 10:30:00 - INFO - ✅ All prerequisites met
2024-01-15 10:30:00 - INFO - 🔄 Step 1: Converting signature patterns to JSON...
2024-01-15 10:30:01 - INFO - ✅ JSON conversion completed successfully
2024-01-15 10:30:01 - INFO - 🔄 Step 2: Converting JSON to YARA rules...
2024-01-15 10:30:01 - INFO - ✅ YARA conversion completed successfully
2024-01-15 10:30:01 - INFO - 🔄 Step 3: Running LLM validation of YARA rules...
2024-01-15 10:30:01 - INFO - 📋 Parsed 237 YARA rules from data/yara_rules.yar
2024-01-15 10:30:01 - INFO - 🎲 Randomly sampling 5 rules for validation
2024-01-15 10:30:01 - INFO - 🚀 Starting validation of 5 rules...
2024-01-15 10:30:01 - INFO - 📊 Progress: 1/5 - backdoor_curl_002
2024-01-15 10:30:02 - INFO - 🔍 Validating rule: backdoor_curl_002
2024-01-15 10:30:02 - INFO - 📊 Progress: 2/5 - backdoor_eval_001
2024-01-15 10:30:03 - INFO - 🔍 Validating rule: backdoor_eval_001
# ... continues for all 5 rules ...
2024-01-15 10:30:06 - INFO - ✅ LLM validation completed successfully
2024-01-15 10:30:06 - INFO - 🔍 Validating output files...
2024-01-15 10:30:06 - INFO - 📊 JSON validation: 237 signatures, 4 constants
2024-01-15 10:30:06 - INFO - 📊 YARA validation: 237 rules generated
2024-01-15 10:30:06 - INFO - ✅ Output validation completed
2024-01-15 10:30:06 - INFO - 🎉 Pipeline completed successfully!

✅ Pipeline completed successfully!
🔍 LLM validation results saved to validation_results_*.json
📋 Check validation.log for detailed validation logs
```

### Check Status
```bash
$ ./run_pipeline.sh --status
🚀 YARA Pipeline Runner with LLM Validation
==================================================
📁 Current directory: /Users/nsimon/code/yara
🔧 Command: python3 scripts/run_pipeline.py --status

Starting pipeline execution...

2024-01-15 10:30:00 - INFO - 📊 Pipeline Status:
2024-01-15 10:30:00 - INFO -    Input file: data/signature_patterns.txt ✅
2024-01-15 10:30:00 - INFO -    JSON file: data/signatures.json ✅
2024-01-15 10:30:00 - INFO -    YARA file: data/yara_rules.yar ✅
2024-01-15 10:30:00 - INFO -    Validation script: scripts/llm_validation.py ✅
2024-01-15 10:30:00 - INFO -    Environment variables: JWT ✅ API_URL ✅

✅ Status check completed!
```

## Contributing

To extend the pipeline:

1. Add new validation steps in `validate_outputs()`
2. Include additional conversion scripts in the pipeline
3. Enhance error handling for specific failure modes
4. Add new command-line options as needed
5. Extend LLM validation prompts for specific use cases
6. Add new validation criteria or scoring methods

## License

This pipeline is part of the YARA project and follows the same licensing terms.
