# YARA Signature Processor

A Python tool for converting signature pattern text files to structured JSON format, specifically designed for malware detection signatures and cleanup patterns.

## Overview

This project processes signature pattern files containing malware detection signatures, cleanup patterns, triggers, and full chain information. It converts these text-based signatures into a structured JSON format that can be easily consumed by YARA rule generators, security analysis tools, or other applications.

## Features

- **Signature Parsing**: Automatically extracts signature names, cleanup patterns, triggers, and full chains
- **Duplicate Handling**: Detects `--` separators and prefixes subsequent signatures with "duplicate_"
- **Constant Substitution**: Processes cleanup constants and substitutes them in patterns
- **JSON Output**: Generates clean, structured JSON with all signature data
- **Batch Processing**: Handles large signature files with hundreds of signatures
- **Error Handling**: Robust parsing with fallback mechanisms

## Project Structure

```
yara/
├── README.md                 # Project description & usage
├── requirements.txt          # Python dependencies
├── data/                     # Input/output signature data
│   ├── signature_patterns.txt  # Raw input signature file
│   ├── signatures.json         # Normalized JSON signatures
│   └── yara_rules.yar          # Transpiled YARA rules
├── old/                      # Archived/legacy files
├── scripts/                  # Processing & transpilation scripts
│   ├── txt_to_json.py        # Convert raw text signatures → JSON
│   └── transpile_to_yara.py  # Convert JSON signatures → YARA rules

```

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Setup

1. Clone or download the project files
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```bash
python3 txt_to_json.py input_file.txt --output output.json
```

### Command Line Options

- `input_file`: Path to the input signature text file (required)
- `--output` or `-o`: Output JSON file path (optional, defaults to `signatures.json`)

### Examples

```bash
# Convert with default output filename
python3 txt_to_json.py data/signature_patterns.txt

# Convert with custom output filename
python3 txt_to_json.py data/signature_patterns.txt --output my_signatures.json

# Using short option
python3 txt_to_json.py data/signature_patterns.txt -o custom_output.json
```

## Input File Format

The script expects input files in the following format:

### Header Section (Optional)
```
=============================
DB Cleanup Constant Variables
=============================

define('CLEAR_COLUMN', '~^.*$~s');

'script_src' => '~<script[^>]*>...~i'
'spam_link' => '~<a[^>]*>...~i'
```

### Signature Section
```
==============
Signature List
==============

Signature Name: signature.name.001
Cleanup Pattern: ~regex_pattern~
Triggers: ['trigger1', 'trigger2']
Full Chain: ['chain1', 'chain2']

--
Signature Name: signature.name.002
Cleanup Pattern: ~another_pattern~
Triggers: ['trigger3']
Full Chain: ['chain3']
```

### Key Elements

- **Signature Name**: Unique identifier for the signature
- **Cleanup Pattern**: Regular expression pattern for detection
- **Triggers**: Array of trigger strings that activate the signature
- **Full Chain**: Array of chain elements for the attack pattern
- **`--` Separator**: Indicates the next signature should be prefixed with "duplicate_"

## Output Format

The script generates a JSON file with the following structure:

```json
{
  "cleanup_constants": [
    {
      "name": "CLEAR_COLUMN",
      "value": "~^.*$~s"
    },
    {
      "name": "script_src",
      "value": "~<script[^>]*>...~i"
    }
  ],
  "signatures": [
    {
      "name": "signature.name.001",
      "cleanup_pattern": "~regex_pattern~",
      "triggers": ["trigger1", "trigger2"],
      "full_chain": ["chain1", "chain2"]
    },
    {
      "name": "duplicate_signature.name.002",
      "cleanup_pattern": "~another_pattern~",
      "triggers": ["trigger3"],
      "full_chain": ["chain3"]
    }
  ]
}
```

## Duplicate Handling

The script automatically detects `--` separators in the input file. When a `--` is found:

1. The current signature block is processed normally
2. A flag is set to prefix the next signature with "duplicate_"
3. The next signature name is automatically prefixed (e.g., `signature.name` becomes `duplicate_signature.name`)

This is useful for maintaining multiple versions of similar signatures while keeping them distinct in the output.

## Cleanup Constants

The script automatically detects and processes cleanup constants defined in the header section:

- **CLEAR_COLUMN**: Main cleanup pattern
- **script_src**: Script source detection pattern
- **spam_link**: Spam link detection pattern
- **spam_link_text**: Spam link text detection pattern

These constants are substituted into cleanup patterns where appropriate placeholders are used.

## Error Handling

The script includes robust error handling for:

- Missing input files
- Malformed signature blocks
- Invalid JSON output
- File encoding issues

## Performance

- **Processing Speed**: Handles large files efficiently (tested with 237+ signatures)
- **Memory Usage**: Streams file processing to minimize memory footprint
- **Output Size**: Generates compact, well-structured JSON

## Use Cases

### Security Analysis
- Convert signature databases to machine-readable format
- Integrate with SIEM systems
- Feed into automated threat detection pipelines

### YARA Rule Generation
- Use as input for YARA rule creation tools
- Generate rules from existing signature databases
- Maintain signature versioning and updates

### Research and Development
- Analyze signature patterns and trends
- Develop new detection methods
- Share signature data in standardized format

## Troubleshooting

### Common Issues

1. **"Input file not found"**: Check the file path and ensure the file exists
2. **"No signatures processed"**: Verify the input file format matches the expected structure
3. **Encoding errors**: Ensure the input file is UTF-8 encoded

### Debug Mode

For troubleshooting, you can modify the script to add debug output by uncommenting or adding print statements in the processing loops.

## Contributing

To contribute to this project:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is provided as-is for educational and research purposes. Please ensure you have appropriate permissions to use any signature data.

## Support

For issues, questions, or feature requests:

1. Check the troubleshooting section above
2. Review the input file format requirements
3. Verify Python version compatibility
4. Open an issue with detailed error information

## Version History

- **v1.0**: Initial release with basic signature parsing
- **v1.1**: Added duplicate handling with `--` separators
- **v1.2**: Improved regex pattern detection and error handling
- **v1.3**: Enhanced cleanup constant processing and JSON output structure

---

**Note**: This tool is designed for processing security-related signature data. Always ensure you have proper authorization to process and analyze any signature files, and follow your organization's security policies.
