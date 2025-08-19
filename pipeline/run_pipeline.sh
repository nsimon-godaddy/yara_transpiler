#!/bin/bash

# YARA Pipeline Runner Script
# Simple wrapper to run the Python pipeline script

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 YARA Pipeline Runner${NC}"
echo "================================"

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
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --clean     Clean previous output files before running"
    echo "  --status    Show current pipeline status and exit"
    echo "  --help      Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run the pipeline normally"
    echo "  $0 --clean           # Clean outputs and run pipeline"
    echo "  $0 --status          # Check pipeline status"
    echo ""
}

# Parse command line arguments
CLEAN=false
STATUS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean)
            CLEAN=true
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
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
done

# Build the command
CMD="python3 scripts/run_pipeline.py"

if [ "$CLEAN" = true ]; then
    CMD="$CMD --clean"
fi

if [ "$STATUS" = true ]; then
    CMD="$CMD --status"
fi

echo -e "${BLUE}📁 Current directory:${NC} $(pwd)"
echo -e "${BLUE}🔧 Command:${NC} $CMD"
echo ""

# Run the pipeline
echo -e "${GREEN}Starting pipeline execution...${NC}"
echo ""

if $CMD; then
    echo ""
    echo -e "${GREEN}✅ Pipeline completed successfully!${NC}"
else
    echo ""
    echo -e "${RED}💥 Pipeline failed!${NC}"
    echo "Check the logs above for details."
    exit 1
fi
