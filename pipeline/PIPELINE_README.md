# YARA Pipeline Automation

This automation pipeline runs both the `txt_to_json` and `transpile_to_yara` scripts in sequence, converting signature patterns from text format to JSON and then to YARA rules.

## Overview

The pipeline consists of two main steps:

1. **Text to JSON Conversion** (`txt_to_json.py`)
   - Converts `data/signature_patterns.txt` to `data/signatures.json`
   - Parses signature blocks and cleanup constants
   - Handles duplicate signature detection

2. **JSON to YARA Conversion** (`transpile_to_yara.py`)
   - Converts `data/signatures.json` to `data/yara_rules.yar`
   - Generates YARA rules from signature data
   - Sanitizes rule names and escapes strings

## Files

- `scripts/run_pipeline.py` - Main Python pipeline script
- `run_pipeline.sh` - Shell script wrapper for easy execution
- `PIPELINE_README.md` - This documentation file

## Usage

### Option 1: Using the Shell Script (Recommended)

```bash
# Run the complete pipeline
./run_pipeline.sh

# Clean previous outputs and run
./run_pipeline.sh --clean

# Check pipeline status
./run_pipeline.sh --status

# Show help
./run_pipeline.sh --help
```

### Option 2: Using Python Directly

```bash
# Run the complete pipeline
python3 scripts/run_pipeline.py

# Clean previous outputs and run
python3 scripts/run_pipeline.py --clean

# Check pipeline status
python3 scripts/run_pipeline.py --status

# Use custom directories
python3 scripts/run_pipeline.py --data-dir custom_data --scripts-dir custom_scripts
```

## Pipeline Flow

```
data/signature_patterns.txt
           ↓
    txt_to_json.py
           ↓
    data/signatures.json
           ↓
   transpile_to_yara.py
           ↓
    data/yara_rules.yar
```

## Features

- **Automatic Validation**: Checks input files and validates outputs
- **Error Handling**: Comprehensive error reporting with detailed logs
- **Logging**: Both console and file logging (`pipeline.log`)
- **Clean Mode**: Option to remove previous outputs before running
- **Status Checking**: Verify pipeline file status without running
- **Flexible Paths**: Customizable data and scripts directories
- **Progress Tracking**: Real-time progress updates with emojis

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

## Error Handling

The pipeline includes comprehensive error handling:

- **Prerequisites Check**: Verifies all required files exist
- **Subprocess Monitoring**: Captures and reports script output
- **File Validation**: Ensures output files are created and valid
- **Graceful Failure**: Stops execution on first error with detailed reporting

## Logging

Logs are written to both:
- **Console**: Real-time progress updates
- **File**: `pipeline.log` for detailed debugging

Log levels include:
- 🔍 Info: Pipeline progress and status
- ✅ Success: Completed steps
- ❌ Error: Failed operations
- ⚠️ Warning: Non-critical issues

## Requirements

- Python 3.6+
- Access to the `scripts/` and `data/` directories
- Input file: `data/signature_patterns.txt`

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

### Debug Mode

For detailed debugging, check the log file:
```bash
tail -f pipeline.log
```

## Examples

### Basic Pipeline Run
```bash
$ ./run_pipeline.sh
🚀 YARA Pipeline Runner
================================
📁 Current directory: /Users/nsimon/code/yara
🔧 Command: python3 scripts/run_pipeline.py --clean

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
2024-01-15 10:30:01 - INFO - 📊 JSON validation: 25 signatures, 4 constants
2024-01-15 10:30:01 - INFO - 📊 YARA validation: 25 rules generated
2024-01-15 10:30:01 - INFO - ✅ Output validation completed
2024-01-15 10:30:01 - INFO - 🎉 Pipeline completed successfully!

✅ Pipeline completed successfully!
```

### Check Status
```bash
$ ./run_pipeline.sh --status
🚀 YARA Pipeline Runner
================================
📁 Current directory: /Users/nsimon/code/yara
🔧 Command: python3 scripts/run_pipeline.py --status

Starting pipeline execution...

2024-01-15 10:30:00 - INFO - 📊 Pipeline Status:
2024-01-15 10:30:00 - INFO -    Input file: data/signature_patterns.txt ✅
2024-01-15 10:30:00 - INFO -    JSON file: data/signatures.json ✅
2024-01-15 10:30:00 - INFO -    YARA file: data/yara_rules.yar ✅

✅ Pipeline completed successfully!
```

## Contributing

To extend the pipeline:

1. Add new validation steps in `validate_outputs()`
2. Include additional conversion scripts in the pipeline
3. Enhance error handling for specific failure modes
4. Add new command-line options as needed

## License

This pipeline is part of the YARA project and follows the same licensing terms.
