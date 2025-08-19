#!/usr/bin/env python3
"""
Simple Document to JSON Converter
Converts document content to JSON format with exact same information as input
"""
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List
import os

def parse_cleanup_constants(text: str) -> Dict[str, str]:
    """Parse DB cleanup constant variables from the document"""
    constants = {}
    
    # Look for the CLEAR_COLUMN constant
    clear_column_match = re.search(r"define\('CLEAR_COLUMN', '([^']+)'\);", text)
    if clear_column_match:
        constants['CLEAR_COLUMN'] = clear_column_match.group(1)
    
    # Extract other constants (script_src, spam_link, spam_link_text)
    constants_pattern = r"'([^']+)'\s*=>\s*'([^']+)'"
    constant_matches = re.findall(constants_pattern, text)
    
    for name, value in constant_matches:
        constants[name] = value
    
    return constants

def substitute_constants(pattern: str, constants: Dict[str, str]) -> str:
    """Substitute constants in patterns"""
    result = pattern
    
    # Replace <TRIGGER> placeholder with CLEAR_COLUMN if available
    if 'CLEAR_COLUMN' in constants:
        result = result.replace('<TRIGGER>', constants['CLEAR_COLUMN'])
    
    # Replace other constants
    for const_name, const_value in constants.items():
        if const_name != 'CLEAR_COLUMN':  # Already handled above
            result = result.replace(f'<{const_name.upper()}>', const_value)
    
    return result

def parse_signature_block(text: str, constants: Dict[str, str]) -> Dict:
    """Parse a single signature block from text"""
    signature = {}
    
    # Extract signature name
    name_match = re.search(r'Signature Name:\s*(.+)', text)
    if name_match:
        signature['name'] = name_match.group(1).strip()
    
    # Extract cleanup pattern and substitute constants
    pattern_match = re.search(r'Cleanup Pattern:\s*(.+)', text)
    if pattern_match:
        pattern = pattern_match.group(1).strip()
        # Substitute constants in the pattern
        signature['cleanup_pattern'] = substitute_constants(pattern, constants)
    
    # Extract triggers
    triggers_match = re.search(r'Triggers:\s*(\[.+\])', text)
    if triggers_match:
        triggers_str = triggers_match.group(1)
        # Parse the triggers list
        triggers = re.findall(r"'([^']+)'", triggers_str)
        signature['triggers'] = triggers
    
    # Extract full chain
    chain_match = re.search(r'Full Chain:\s*(\[.+\])', text)
    if chain_match:
        chain_str = chain_match.group(1)
        # Parse the chain list
        chain = re.findall(r"'([^']+)'", chain_str)
        signature['full_chain'] = chain
    
    return signature



def convert_doc_to_json(input_file: str, output_file: str):
    """Convert document content to JSON format"""
    # Use the input and output paths as provided (they should be relative to current working directory)
    input_path = input_file
    output_path = output_file


    with open(input_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Parse cleanup constants first
    constants = parse_cleanup_constants(content)
    print(f"🔧 Found {len(constants)} cleanup constants: {list(constants.keys())}")
    
    # Split content into signature blocks
    # Look for patterns that indicate signature boundaries

    # Split content into signature blocks by looking for "Signature Name:" patterns
    signature_blocks = re.split(r'\n(?=Signature Name:)', content)
    
    signatures = []
    duplicate_next = False

    for block in signature_blocks:
        block = block.strip()
        if not block or not block.startswith('Signature Name:'):
            continue
        
        signature = parse_signature_block(block, constants)
        name = signature.get('name')
        if not name:
            continue

        # If the previous block contained "--", prefix this signature with "duplicate_"
        if duplicate_next:
            signature['name'] = f'duplicate_{name}'
            duplicate_next = False
        
        # Check if this block contains standalone "--" to mark the next signature as duplicate
        # Look for "--" that's on its own line or surrounded by whitespace
        if re.search(r'(?:^|\n)\s*--\s*(?:\n|$)', block):
            duplicate_next = True

        signatures.append(signature)
        print(f"✅ Processed signature: {signature['name']}")

    # Create the JSON structure with cleanup constants at the top
    json_data = {
        "cleanup_constants": [
            {"name": k, "value": v} for k, v in constants.items()
        ],
        "signatures": signatures
    }
    
    # Save to output file
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Converted {len(signatures)} signatures to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Convert document content to JSON format')
    parser.add_argument('input_file', help='Input document file with signature information')
    parser.add_argument('--output', '-o', default='signatures.json', help='Output JSON file')
    
    args = parser.parse_args()
    
    if not Path(args.input_file).exists():
        print(f"❌ Input file {args.input_file} not found")
        return
    
    convert_doc_to_json(args.input_file, args.output)

if __name__ == "__main__":
    main() 