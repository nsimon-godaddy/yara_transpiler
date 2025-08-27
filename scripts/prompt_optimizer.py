#!/usr/bin/env python3
"""
Prompt Optimization Layer for YARA Rule Generation
Analyzes non-text files and generates optimized prompts for LLM-based YARA rule generation.
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional
import base64
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('prompt_optimization.log')
    ]
)
logger = logging.getLogger(__name__)

class PromptOptimizer:
    """Analyzes files and generates optimized prompts for LLM-based YARA rule generation"""
    
    def __init__(self, input_file: str):
        self.input_file = Path(input_file)
        self.prompt_templates = self._load_prompt_templates()
        
    def _load_prompt_templates(self) -> Dict[str, str]:
        """Load prompt templates for different file types"""
        return {
            'executable': """Task: Convert this signature/indicator into a syntactically correct YARA rule.

Context: The source is {file_type}. Analyze the file content to identify key characteristics, patterns, and behaviors.

Constraints: Follow YARA syntax rules, avoid unsupported regex (no (?:...) groups, no backreferences), explain condition logic.

Output format: Return only a valid YARA rule.""",
            
            'script': """⚠️  CRITICAL YARA SYNTAX WARNING - READ FIRST ⚠️

🚫 ABSOLUTELY FORBIDDEN - These will cause syntax errors and break your rules:
- 'filetype == "php"' - This identifier does NOT exist in YARA
- 'file_type == "exe"' - This identifier does NOT exist in YARA
- Any other file type identifiers that aren't defined as strings

✅ ALWAYS use proper file type detection with defined strings and magic bytes.

Task: Convert this signature/indicator into a syntactically correct YARA rule.

Context: The source is {file_type}. For PHP files, focus on analyzing the actual code behavior, function calls, variable usage, and execution patterns. Ignore documentation, comments, HTML content, and echo/print statements as they are often just malware author descriptions.

Example of a good PHP YARA rule:
rule PHP_Webshell_Example {{
    meta:
        description = "Detects PHP webshell with code execution capabilities"
        author = "Security Analyst"
        severity = "HIGH"
        category = "MALWARE"
    
    strings:
        $eval_func = "eval(" ascii
        $php_header = "<?php" ascii
        $php_short = "<?=" ascii
        $system_func = "system(" ascii
        $exec_func = "exec(" ascii
        $shell_exec = "shell_exec(" ascii
        $passthru_func = "passthru(" ascii
        $file_get_contents = "file_get_contents(" ascii
        $file_put_contents = "file_put_contents(" ascii
        $unlink_func = "unlink(" ascii
        $chmod_func = "chmod(" ascii
    
    condition:
        ($php_header or $php_short) and
        3 of ($eval_func, $system_func, $exec_func, $shell_exec, $passthru_func) and
        2 of ($file_get_contents, $file_put_contents, $unlink_func, $chmod_func)
}}

IMPORTANT YARA SYNTAX RULES - READ CAREFULLY:

🚫 NEVER USE THESE INVALID IDENTIFIERS:
- 'filetype' - This identifier does NOT exist in YARA
- 'file_type' - This identifier does NOT exist in YARA
- Any other file type identifiers that aren't defined as strings

✅ ALWAYS USE THESE CORRECT FILE TYPE DETECTION METHODS:

1. PHP FILES:
   - Use: '$php_header = "<?php" ascii' and '$php_short = "<?=" ascii'
   - Condition: '($php_header or $php_short) and ...'
   - NEVER use: 'filetype == "php"'

2. EXECUTABLE FILES:
   - Use: '$pe_header = {{ 4D 5A }}' (MZ magic bytes)
   - Use: '$elf_header = {{ 7F 45 4C 46 }}' (ELF magic bytes)
   - Condition: '$pe_header at 0' or '$elf_header at 0'

3. ZIP FILES:
   - Use: '$zip_header = {{ 50 4B 03 04 }}' (PK magic bytes)
   - Condition: '$zip_header at 0'

4. PDF FILES:
   - Use: '$pdf_header = "%PDF" ascii'
   - Condition: '$pdf_header at 0'

5. DOC FILES:
   - Use: '$doc_header = {{ D0 CF 11 E0 A1 B1 1A E1 }}'
   - Condition: '$doc_header at 0'

Constraints: Follow YARA syntax rules, avoid unsupported regex (no (?:...) groups, no backreferences), focus on detecting malicious code patterns and behaviors. Prioritize function calls, variable manipulation, and execution patterns over text output. AVOID using descriptive text strings from echo/print statements as they are unreliable and change frequently.

Output format: Return only a valid YARA rule.""",
            
            'document': """⚠️  CRITICAL YARA SYNTAX WARNING - READ FIRST ⚠️

🚫 ABSOLUTELY FORBIDDEN - These will cause syntax errors and break your rules:
- 'filetype == "php"' - This identifier does NOT exist in YARA
- 'file_type == "exe"' - This identifier does NOT exist in YARA
- Any other file type identifiers that aren't defined as strings

✅ ALWAYS use proper file type detection with defined strings and magic bytes.

Task: Convert this signature/indicator into a syntactically correct YARA rule.

Context: The source is {file_type}. Analyze the file content to identify key characteristics, patterns, and behaviors.

Constraints: Follow YARA syntax rules, avoid unsupported regex (no (?:...) groups, no backreferences), explain condition logic.

Output format: Return only a valid YARA rule.""",
            
            'archive': """⚠️  CRITICAL YARA SYNTAX WARNING - READ FIRST ⚠️

🚫 ABSOLUTELY FORBIDDEN - These will cause syntax errors and break your rules:
- 'filetype == "php"' - This identifier does NOT exist in YARA
- 'file_type == "exe"' - This identifier does NOT exist in YARA
- Any other file type identifiers that aren't defined as strings

✅ ALWAYS use proper file type detection with defined strings and magic bytes.

Task: Convert this signature/indicator into a syntactically correct YARA rule.

Context: The source is {file_type}. Analyze the file content to identify key characteristics, patterns, and behaviors.

Constraints: Follow YARA syntax rules, avoid unsupported regex (no (?:...) groups, no backreferences), explain condition logic.

Output format: Return only a valid YARA rule.""",
            
            'text': """⚠️  CRITICAL YARA SYNTAX WARNING - READ FIRST ⚠️

🚫 ABSOLUTELY FORBIDDEN - These will cause syntax errors and break your rules:
- 'filetype == "php"' - This identifier does NOT exist in YARA
- 'file_type == "exe"' - This identifier does NOT exist in YARA
- Any other file type identifiers that aren't defined as strings

✅ ALWAYS use proper file type detection with defined strings and magic bytes.

Task: Convert this signature/indicator into a syntactically correct YARA rule.

Context: The source is {file_type}. Analyze the file content to identify key characteristics, patterns, and behaviors.

Constraints: Follow YARA syntax rules, avoid unsupported regex (no (?:...) groups, no backreferences), explain condition logic.

Output format: Return only a valid YARA rule.""",
            
            'default': """⚠️  CRITICAL YARA SYNTAX WARNING - READ FIRST ⚠️

🚫 ABSOLUTELY FORBIDDEN - These will cause syntax errors and break your rules:
- 'filetype == "php"' - This identifier does NOT exist in YARA
- 'file_type == "exe"' - This identifier does NOT exist in YARA
- Any other file type identifiers that aren't defined as strings

✅ ALWAYS use proper file type detection with defined strings and magic bytes.

Task: Convert this signature/indicator into a syntactically correct YARA rule.

Context: The source is {file_type}. Analyze the file content to identify key characteristics, patterns, and behaviors.

Constraints: Follow YARA syntax rules, avoid unsupported regex (no (?:...) groups, no backreferences), explain condition logic.

Output format: Return only a valid YARA rule."""
        }
    
    def analyze_file(self) -> Dict:
        """Analyze the input file and extract characteristics"""
        try:
            # Get basic file info
            file_extension = self.input_file.suffix.lower()
            
            # Read file content
            with open(self.input_file, 'rb') as f:
                content = f.read()
            
            # Determine file type category
            file_type_category = self._categorize_file_type(file_extension, content)
            
            # Extract key characteristics
            characteristics = self._extract_characteristics(content, file_extension)
            
            analysis = {
                'file_path': str(self.input_file),
                'file_name': self.input_file.name,
                'file_extension': file_extension,
                'file_type_category': file_type_category,
                'characteristics': characteristics,
                'content_sample': content[:1000].decode('utf-8', errors='ignore') if len(content) > 1000 else content.decode('utf-8', errors='ignore')
            }
            
            logger.info(f"📋 File analysis completed for {self.input_file.name}")
            return analysis
            
        except Exception as e:
            logger.error(f"❌ File analysis failed: {e}")
            raise
    

    
    def _categorize_file_type(self, extension: str, content: bytes) -> str:
        """Categorize file type based on extension and content"""
        # Check for executable signatures
        if extension in ['.exe', '.dll', '.so', '.dylib'] or content.startswith(b'MZ') or content.startswith(b'\x7fELF'):
            return 'executable'
        
        # Check for script files
        if extension in ['.py', '.php', '.js', '.vbs', '.ps1', '.sh', '.bat', '.cmd']:
            return 'script'
        
        # Check for document files
        if extension in ['.doc', '.docx', '.pdf', '.rtf', '.txt', '.md']:
            return 'document'
        
        # Check for archive files
        if extension in ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']:
            return 'archive'
        
        # Check if content looks like text
        try:
            content.decode('utf-8')
            return 'text'
        except UnicodeDecodeError:
            pass
        
        return 'default'
    
    def _extract_characteristics(self, content: bytes, extension: str) -> List[str]:
        """Let AI analyze the file content directly - return minimal info"""
        # Just return basic file type info, let AI do the analysis
        return [f"File extension: {extension}"]
    
    def generate_optimized_prompt(self, analysis: Dict) -> str:
        """Generate an optimized prompt based on file analysis"""
        file_type_category = analysis['file_type_category']
        
        # Select appropriate template
        template = self.prompt_templates.get(file_type_category, self.prompt_templates['default'])
        
        # Format template with analysis data
        optimized_prompt = template.format(
            file_type=analysis['file_extension'],
            characteristics=', '.join(analysis['characteristics'])
        )
        
        logger.info(f"🎯 Generated optimized prompt for {file_type_category} file type")
        return optimized_prompt
    
    def save_optimization_results(self, analysis: Dict, optimized_prompt: str, output_file: str = None) -> str:
        """Save optimization results to file"""
        if not output_file:
            timestamp = analysis['file_name'].replace('.', '_')
            output_file = f"prompt_optimization_{timestamp}.json"
        
        results = {
            'file_analysis': analysis,
            'optimized_prompt': optimized_prompt,
            'file_type_category': analysis['file_type_category']
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Optimization results saved to: {output_file}")
        return output_file

def main():
    parser = argparse.ArgumentParser(
        description="Optimize prompts for LLM-based YARA rule generation"
    )
    parser.add_argument(
        "input_file",
        help="Path to input file to analyze"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for optimization results"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize optimizer
        optimizer = PromptOptimizer(args.input_file)
        
        # Analyze file
        analysis = optimizer.analyze_file()
        
        # Generate optimized prompt
        optimized_prompt = optimizer.generate_optimized_prompt(analysis)
        
        # Save results
        output_file = optimizer.save_optimization_results(analysis, optimized_prompt, args.output)
        
        # Print summary
        print("\n" + "="*60)
        print("🎯 PROMPT OPTIMIZATION SUMMARY")
        print("="*60)
        print(f"📁 File: {analysis['file_name']}")
        print(f"🔧 Type: {analysis['file_type_category']}")
        print(f"🎯 Characteristics: {', '.join(analysis['characteristics'])}")
        print("="*60)
        
        print("\n📝 OPTIMIZED PROMPT:")
        print("-" * 40)
        print(optimized_prompt)
        print("-" * 40)
        
        print(f"\n📁 Results saved to: {output_file}")
        
    except Exception as e:
        logger.error(f"💥 Prompt optimization failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
