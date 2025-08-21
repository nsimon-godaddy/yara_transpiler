#!/bin/bash

# YARA Pipeline Runner Script with LLM Validation
# Simple wrapper to run the Python pipeline script

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 YARA Pipeline Runner with LLM Validation${NC}"
echo "=================================================="

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python 3 is not installed or not in PATH${NC}"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "scripts/run_pipeline.py" ]; then
    echo -e "${RED}❌ Please run this script from the project root directory${NC}"
    echo "   (where scripts/run_pipeline.py is located)"
    exit 1
fi

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS] [INPUT_FILES...]"
    echo ""
    echo "File Arguments:"
    echo "  INPUT_FILES        One or more input text files (default: data/signature_patterns.txt)"
    echo "                     Multiple files will be processed sequentially"
    echo ""
    echo "Pipeline Options:"
    echo "  --clean           Clean previous output files before running"
    echo "  --validate        Run LLM validation after YARA generation"
    echo "  --max-rules N     Validate maximum N rules (requires --validate)"
    echo "  --sample N        Randomly sample N rules for validation (requires --validate)"
    echo "  --skip-classification  Skip data classification step"
    echo "  --output FILE     Output file for validation results"
    echo ""
    echo "Utility Options:"
    echo "  --status          Show current pipeline status and exit"
    echo "  --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run with default files"
    echo "  $0 my_patterns.txt                    # Use single custom input file"
    echo "  $0 file1.txt file2.txt file3.txt     # Process multiple input files"
    echo "  $0 --clean                            # Clean and run with defaults"
    echo "  $0 --validate                         # Run with LLM validation"
    echo "  $0 --validate --sample 5              # Validate random 5 rules"
    echo "  $0 --validate --output results.json   # Validate with custom output file"
    echo "  $0 --skip-classification              # Skip data classification step"
    echo "  $0 --status                           # Check pipeline status"
    echo ""
    echo "Note: LLM validation requires JWT and API_URL environment variables"
}

# Parse command line arguments
CLEAN=false
VALIDATE=false
MAX_RULES=""
SAMPLE=""
OUTPUT=""
SKIP_CLASSIFICATION=false
STATUS=false

# Array to store input files
INPUT_FILES=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=true
            shift
            ;;
        --validate)
            VALIDATE=true
            shift
            ;;
        --max-rules)
            MAX_RULES="$2"
            shift 2
            ;;
        --sample)
            SAMPLE="$2"
            shift
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --skip-classification)
            SKIP_CLASSIFICATION=true
            shift
            ;;
        --status)
            STATUS=true
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        -*)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            show_usage
            exit 1
            ;;
        *)
            # This is a file argument - add to input files array
            INPUT_FILES+=("$1")
            shift
            ;;
    esac
done

# Validate argument combinations
if [ "$VALIDATE" = false ] && ([ -n "$MAX_RULES" ] || [ -n "$SAMPLE" ]); then
    echo -e "${RED}❌ --max-rules and --sample require --validate flag${NC}"
    exit 1
fi

# Build the command
CMD="python3 scripts/run_pipeline.py"

# Add input files if provided
if [ ${#INPUT_FILES[@]} -gt 0 ]; then
    for file in "${INPUT_FILES[@]}"; do
        CMD="$CMD $file"
    done
fi

if [ "$CLEAN" = true ]; then
    CMD="$CMD --clean"
fi

if [ "$VALIDATE" = true ]; then
    CMD="$CMD --validate"
    
    if [ -n "$MAX_RULES" ]; then
        CMD="$CMD --max-rules $MAX_RULES"
    fi
    
    if [ -n "$SAMPLE" ]; then
        CMD="$CMD --sample $SAMPLE"
    fi
fi

if [ -n "$OUTPUT" ]; then
    CMD="$CMD --output $OUTPUT"
fi

if [ "$SKIP_CLASSIFICATION" = true ]; then
    CMD="$CMD --skip-classification"
fi

if [ "$STATUS" = true ]; then
    CMD="$CMD --status"
fi

echo -e "${BLUE}📁 Current directory:${NC} $(pwd)"
echo -e "${BLUE}🔧 Command:${NC} $CMD"
echo ""

# Check environment variables for validation
if [ "$VALIDATE" = true ]; then
    if [ -z "$JWT" ] || [ -z "$API_URL" ]; then
        echo -e "${YELLOW}⚠️  Warning: JWT or API_URL environment variables not set${NC}"
        echo -e "${YELLOW}   LLM validation may fail. Check your .env file.${NC}"
        echo ""
    else
        echo -e "${GREEN}✅ Environment variables found for LLM validation${NC}"
        echo ""
    fi
fi

# Run the pipeline
if [ "$STATUS" = true ]; then
    echo -e "${BLUE}Checking pipeline status...${NC}"
else
    echo -e "${GREEN}Starting pipeline execution...${NC}"
fi

echo ""

# Export environment variables for the Python subprocess
if [ -f ".env" ]; then
    echo -e "${BLUE}📋 Loading environment variables from .env file...${NC}"
    export $(cat .env | grep -v '^#' | xargs)
fi

if $CMD; then
    echo ""
    if [ "$STATUS" = true ]; then
        echo -e "${GREEN}✅ Status check completed!${NC}"
    else
        echo -e "${GREEN}✅ Pipeline completed successfully!${NC}"
        
        if [ "$VALIDATE" = true ]; then
            echo -e "${PURPLE}🔍 LLM validation results saved to validation_results_*.json${NC}"
            echo -e "${PURPLE}📋 Check validation.log for detailed validation logs${NC}"
        fi
    fi
else
    echo ""
    echo -e "${RED}💥 Pipeline failed!${NC}"
    echo "Check the logs above for details."
    exit 1
fi

