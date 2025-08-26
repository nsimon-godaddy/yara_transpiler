#!/usr/bin/env python3
"""
Data Classification Layer
Uses Gocaas API to determine if JSON data is in a recognized form suitable for YARA conversion
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional
from dotenv import load_dotenv
import requests
from datetime import datetime
import base64
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('classification.log')
    ]
)
logger = logging.getLogger(__name__)

class DataClassifier:
    """Data classifier using Gocaas API to determine data structure suitability"""
    
    def __init__(self, input_file: str):
        # Load environment variables
        load_dotenv()
        
        self.jwt = os.getenv("JWT")
        self.api_url = os.getenv("API_URL")
        
        if not self.jwt or not self.api_url:
            raise ValueError("JWT and API_URL environment variables must be set")
        
        self.input_file = Path(input_file)
        
        # API configuration
        self.api_config = {
            "isPrivate": True,
            "provider": "anthropic_chat",
            "providerOptions": {
                "model": "claude-3-5-haiku-20241022-v1:0",
                "max_tokens": 2048
            }
        }
        
        self.headers = {
            "Authorization": f"sso-jwt {self.jwt}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
    
    def load_input_data(self) -> str:
        """Load and parse input data"""
        if not self.input_file.exists():
            raise FileNotFoundError(f"Input file not found: {self.input_file}")
        
        # Check file extension
        file_extension = self.input_file.suffix.lower()
        
        try:
            if file_extension == '.txt':
                # Text file - read as text
                with open(self.input_file, 'r', encoding='utf-8') as f:
                    data = f.read()
                logger.info(f"📋 Loaded text data from {self.input_file}")
                return data
            else:
                # Non-text file - read as binary and convert to base64 for LLM processing
                with open(self.input_file, 'rb') as f:
                    binary_data = f.read()
                
                # For PHP files, filter out documentation and focus on code
                if file_extension == '.php':
                    filtered_data = self._filter_php_content(binary_data)
                    base64_data = base64.b64encode(filtered_data).decode('utf-8')
                    logger.info(f"📋 Loaded and filtered PHP data from {self.input_file} (size: {len(filtered_data)} bytes)")
                    return f"BINARY_FILE:{file_extension}:{base64_data}"
                else:
                    base64_data = base64.b64encode(binary_data).decode('utf-8')
                    logger.info(f"📋 Loaded binary data from {self.input_file} (size: {len(binary_data)} bytes)")
                    return f"BINARY_FILE:{file_extension}:{base64_data}"
                
        except Exception as e:
            raise ValueError(f"Error loading input file: {e}")
    
    def _filter_php_content(self, binary_data: bytes) -> bytes:
        """Filter PHP content to focus on actual code, removing documentation and comments"""
        try:
            # Decode binary data to text
            content = binary_data.decode('utf-8', errors='ignore')
            
            # Remove PHP opening tags and any initial whitespace/comments
            lines = content.split('\n')
            filtered_lines = []
            code_started = False
            
            for line in lines:
                stripped = line.strip()
                
                # Skip empty lines at the beginning
                if not stripped and not code_started:
                    continue
                
                # Skip comment lines (// or #)
                if stripped.startswith('//') or stripped.startswith('#'):
                    continue
                
                # Skip multi-line comment blocks
                if stripped.startswith('/*') or stripped.startswith('*'):
                    continue
                
                # Skip HTML comment lines
                if stripped.startswith('<!--'):
                    continue
                
                # Look for actual PHP code (<?php, <?, or function/class definitions)
                # Skip echo/print statements as they're often just documentation
                if ('<?php' in stripped or '<?' in stripped or 
                    stripped.startswith('function ') or 
                    stripped.startswith('class ') or
                    stripped.startswith('$') or
                    stripped.startswith('if ') or
                    stripped.startswith('for ') or
                    stripped.startswith('while ') or
                    stripped.startswith('foreach ') or
                    stripped.startswith('return ') or
                    stripped.startswith('include ') or
                    stripped.startswith('require ') or
                    stripped.startswith('eval(') or
                    stripped.startswith('system(') or
                    stripped.startswith('exec(') or
                    stripped.startswith('shell_exec(') or
                    stripped.startswith('passthru(') or
                    stripped.startswith('$_') or
                    stripped.startswith('$GLOBALS') or
                    stripped.startswith('$SERVER') or
                    stripped.startswith('$REQUEST') or
                    stripped.startswith('$POST') or
                    stripped.startswith('$GET') or
                    stripped.startswith('$FILES') or
                    stripped.startswith('$COOKIE') or
                    stripped.startswith('$SESSION')):
                    code_started = True
                
                # Once code has started, include all lines
                if code_started:
                    filtered_lines.append(line)
            
            # If no code was found, return original content
            if not filtered_lines:
                logger.warning("⚠️  No PHP code patterns found, returning original content")
                return binary_data
            
            # Reconstruct filtered content
            filtered_content = '\n'.join(filtered_lines)
            
            # Additional filtering: Remove echo and print statements that are often just documentation
            filtered_content = self._remove_echo_statements(filtered_content)
            
            logger.info(f"🔍 Filtered PHP content: removed {len(lines) - len(filtered_lines)} documentation lines")
            
            return filtered_content.encode('utf-8')
            
        except Exception as e:
            logger.warning(f"⚠️  PHP filtering failed: {e}, returning original content")
            return binary_data
    
    def _remove_echo_statements(self, content: str) -> str:
        """Remove echo and print statements that are often just malware author documentation"""
        try:
            lines = content.split('\n')
            filtered_lines = []
            
            for line in lines:
                stripped = line.strip()
                
                # Skip echo and print statements that are likely just documentation
                if (stripped.startswith('echo ') or 
                    stripped.startswith('print ') or
                    stripped.startswith('echo(') or
                    stripped.startswith('print(')):
                    
                    # Skip echo/print statements as they're almost always just documentation
                    # Only keep them if they contain actual code patterns
                    if not any(pattern in stripped for pattern in ['$_', '$GLOBALS', 'function', 'eval(', 'system(', 'exec(']):
                        continue  # Skip this line as it's just documentation
                
                # Keep the line if it's not just documentation
                filtered_lines.append(line)
            
            filtered_content = '\n'.join(filtered_lines)
            logger.info(f"🔍 Removed echo/print documentation statements from PHP content")
            
            return filtered_content
            
        except Exception as e:
            logger.warning(f"⚠️  Echo statement removal failed: {e}, returning original content")
            return content
    
    def get_classification_prompt(self, data: str, custom_prompt: str = None) -> List[Dict]:
        """Generate classification prompt for the input data"""
        
        # If a custom prompt is provided, combine it with the file data
        if custom_prompt:
            logger.info("📝 Using custom optimized prompt for classification")
            if data.startswith("BINARY_FILE:"):
                # For binary files, combine custom prompt with file data
                return self._get_custom_binary_file_prompt(data, custom_prompt)
            else:
                # For text files, combine custom prompt with text data
                return self._get_custom_text_file_prompt(data, custom_prompt)
        
        # Check if this is a binary file
        if data.startswith("BINARY_FILE:"):
            return self._get_binary_file_prompt(data)
        else:
            return self._get_text_file_prompt(data)
    
    def _get_text_file_prompt(self, data: str) -> List[Dict]:
        """Generate classification prompt for text files"""
        
        system_prompt = """Task: Determine if this text file is suitable for YARA rule generation.

Context: Analyze if the file follows a format suitable for YARA conversion (similar to signature_patterns.txt).

Constraints: Check format compatibility, data structure, and YARA suitability.

Output format: Return analysis of format compatibility and YARA suitability."""
        
        # Create a sample of the data for analysis (limit size for API)
        data_sample = self._create_text_sample(data)
        
        user_prompt = f"""INPUT DATA TO CLASSIFY:
{data_sample}

Analyze format compatibility and YARA suitability."""
        
        return [
            {"from": "system", "content": system_prompt},
            {"from": "user", "content": user_prompt}
        ]
    
    def _get_binary_file_prompt(self, data: str) -> List[Dict]:
        """Generate classification prompt for binary files"""
        
        system_prompt = """Task: Convert this signature/indicator into a syntactically correct YARA rule.

Context: The source is a base64-encoded file. For PHP files, focus on analyzing the actual code behavior, function calls, variable usage, and execution patterns. Ignore documentation, comments, HTML content, and echo/print statements as they are often just malware author descriptions.

Example of a good PHP YARA rule:
rule PHP_Webshell_Example {{
    meta:
        description = "Detects PHP webshell with code execution capabilities"
        author = "Security Analyst"
        severity = "HIGH"
        category = "MALWARE"
    
    strings:
        $eval_func = "eval(" ascii
        $system_func = "system(" ascii
        $exec_func = "exec(" ascii
        $shell_exec = "shell_exec(" ascii
        $passthru_func = "passthru(" ascii
        $file_get_contents = "file_get_contents(" ascii
        $file_put_contents = "file_put_contents(" ascii
        $unlink_func = "unlink(" ascii
        $chmod_func = "chmod(" ascii
    
    condition:
        filetype == "php" and
        3 of ($eval_func, $system_func, $exec_func, $shell_exec, $passthru_func) and
        2 of ($file_get_contents, $file_put_contents, $unlink_func, $chmod_func)
}}

Constraints: Follow YARA syntax rules, avoid unsupported regex (no (?:...) groups, no backreferences), focus on detecting malicious code patterns and behaviors. Prioritize function calls, variable manipulation, and execution patterns over text output. AVOID using descriptive text strings from echo/print statements as they are unreliable and change frequently.

Output format: Return only a valid YARA rule."""
        
        # Extract file info from the data
        parts = data.split(":", 2)
        file_extension = parts[1] if len(parts) > 1 else "unknown"
        base64_data = parts[2] if len(parts) > 2 else ""
        
        # Limit base64 data size for API
        if len(base64_data) > 1000:
            base64_data = base64_data[:1000] + "... [truncated]"
        
        user_prompt = f"""BINARY FILE TO ANALYZE:
File Extension: {file_extension}
Base64 Data: {base64_data}

Create a YARA rule for detection."""
        
        return [
            {"from": "system", "content": system_prompt},
            {"from": "user", "content": user_prompt}
        ]

    def _get_custom_binary_file_prompt(self, data: str, custom_prompt: str) -> List[Dict]:
        """Generate custom prompt for binary files with file data included"""
        
        # Extract file info from the data
        parts = data.split(":", 2)
        file_extension = parts[1] if len(parts) > 1 else "unknown"
        base64_data = parts[2] if len(parts) > 2 else ""
        
        # Limit base64 data size for API
        if len(base64_data) > 1000:
            base64_data = base64_data[:1000] + "... [truncated]"
        
        # Combine custom prompt with file data
        combined_prompt = f"""{custom_prompt}

BINARY FILE TO ANALYZE:
File Extension: {file_extension}
Base64 Data: {base64_data}

For PHP files: Focus on the actual code behavior, function calls, and execution patterns. Ignore documentation, comments, HTML content, and echo/print statements as they are often just malware author descriptions. Prioritize function calls, variable manipulation, and execution patterns over text output. AVOID using descriptive text strings from echo/print statements as they are unreliable and change frequently.

Example of good PHP YARA rule structure:
- Use function names like eval(, system(, exec(, file_get_contents(
- Use variable patterns like $_GET, $_POST, $_FILES, $_SERVER
- Use file operations like chmod(, unlink(, include, require
- Avoid descriptive text strings from echo/print statements
Please analyze this file content and create a YARA rule."""
        
        return [
            {"from": "user", "content": combined_prompt}
        ]

    def _get_custom_text_file_prompt(self, data: str, custom_prompt: str) -> List[Dict]:
        """Generate custom prompt for text files with file data included"""
        
        # Create a sample of the data for analysis
        data_sample = self._create_text_sample(data)
        
        # Combine custom prompt with file data
        combined_prompt = f"""{custom_prompt}

INPUT DATA TO ANALYZE:
{data_sample}

Please analyze this file content and create a YARA rule."""
        
        return [
            {"from": "user", "content": combined_prompt}
        ]


    
    def _create_text_sample(self, data: str) -> str:
        """Create a manageable sample of the text data for API analysis"""
        # Limit to first 2000 characters to avoid API limits
        if len(data) > 2000:
            sample = data[:2000] + "\n\n... [truncated for analysis]"
        else:
            sample = data
        
        return sample
    
    def classify_data(self, data: str, custom_prompt: str = None) -> Dict:
        """Classify the input data using Gocaas API"""
        try:
            prompts = self.get_classification_prompt(data, custom_prompt)
            
            payload = {
                "prompts": prompts,
                **self.api_config
            }
            
            logger.info("🔍 Classifying input data structure using Gocaas API...")
            
            response = requests.post(
                self.api_url, 
                headers=self.headers, 
                json=payload,
                timeout=60
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                classification_content = result.get("data", {}).get("value", {}).get("content", "")
                
                # Parse the classification response
                classification_result = self._parse_classification_response(classification_content, data)
                
                return {
                    'status': 'classified',
                    'classification_content': classification_content,
                    'analysis': classification_result,
                    'timestamp': datetime.now().isoformat(),
                    'api_response': result
                }
            else:
                logger.error(f"API request failed: {response.status_code}")
                return {
                    'status': 'api_error',
                    'error': f"HTTP {response.status_code}: {response.text}",
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Classification failed: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def _parse_classification_response(self, content: str, data: str) -> Dict:
        """Parse the LLM classification response to extract key information"""
        analysis = {
            'format_compatibility': 'UNKNOWN',
            'recognition_status': 'UNKNOWN',
            'data_type': 'UNKNOWN',
            'yara_compatibility': 'UNKNOWN',
            'conversion_readiness': 0,
            'can_proceed': False
        }
        
        # Check if this is a binary file
        if data.startswith("BINARY_FILE:"):
            return self._parse_binary_file_response(content, data)
        
        # Extract key information from the response for text files
        content_lower = content.lower()
        
        # Check format compatibility (most important)
        if 'yes' in content_lower and 'format compatibility' in content_lower:
            analysis['format_compatibility'] = 'YES'
        elif 'no' in content_lower and 'format compatibility' in content_lower:
            analysis['format_compatibility'] = 'NO'
        
        # Check recognition status
        if 'yes' in content_lower and 'recognized' in content_lower:
            analysis['recognition_status'] = 'YES'
        elif 'no' in content_lower and 'recognized' in content_lower:
            analysis['recognition_status'] = 'NO'
        
        # Check YARA compatibility
        if 'yes' in content_lower and 'yara' in content_lower and 'conversion' in content_lower:
            analysis['yara_compatibility'] = 'YES'
        elif 'no' in content_lower and 'yara' in content_lower and 'conversion' in content_lower:
            analysis['yara_compatibility'] = 'NO'
        
        # Extract conversion readiness score
        import re
        score_match = re.search(r'(\d+)/10', content)
        if score_match:
            analysis['conversion_readiness'] = int(score_match.group(1))
        
        # Determine if we can proceed - NOW REQUIRES FORMAT COMPATIBILITY
        # If format validation passes, we can proceed even with lower AI scores
        analysis['can_proceed'] = (
            analysis['format_compatibility'] == 'YES' and
            analysis['yara_compatibility'] == 'YES' and
            analysis['conversion_readiness'] >= 5  # Lowered threshold since format validation is more reliable
        )
        
        # Add data statistics for text analysis
        analysis['data_stats'] = self._analyze_text_structure(data)
        
        # Add format validation
        analysis['format_validation'] = self._validate_text_format(data)
        
        return analysis
    
    def _parse_binary_file_response(self, content: str, data: str) -> Dict:
        """Parse the LLM response for binary file analysis"""
        analysis = {
            'format_compatibility': 'BINARY_FILE',
            'recognition_status': 'YES',
            'data_type': 'BINARY_FILE',
            'yara_compatibility': 'YES',
            'conversion_readiness': 10,
            'can_proceed': True,
            'is_binary_file': True
        }
        
        # Extract file info
        parts = data.split(":", 2)
        file_extension = parts[1] if len(parts) > 1 else "unknown"
        
        # Add binary file specific data
        analysis['data_stats'] = {
            'file_type': file_extension,
            'is_binary': True,
            'processing_method': 'LLM_YARA_GENERATION'
        }
        
        # Add format validation for binary files
        analysis['format_validation'] = {
            'is_binary_file': True,
            'file_extension': file_extension,
            'can_generate_yara': True
        }
        
        return analysis
    
    def _analyze_text_structure(self, data: str) -> Dict:
        """Analyze the text structure for statistics"""
        stats = {
            'total_lines': 0,
            'has_cleanup_section': False,
            'has_signature_section': False,
            'signature_count': 0,
            'cleanup_constant_count': 0
        }
        
        lines = data.split('\n')
        stats['total_lines'] = len(lines)
        
        # Check for cleanup constants section
        if 'DB Cleanup Constant Variables' in data:
            stats['has_cleanup_section'] = True
            # Count define statements
            stats['cleanup_constant_count'] = data.count("define('")
        
        # Check for signature section
        if 'Signature List' in data:
            stats['has_signature_section'] = True
            # Count signature entries
            stats['signature_count'] = data.count('Signature Name:')
        
        return stats
    
    def _validate_text_format(self, data: str) -> Dict:
        """Validate the exact text format expected by the pipeline"""
        validation = {
            'has_cleanup_section': False,
            'has_signature_section': False,
            'has_define_statements': False,
            'has_signature_entries': False,
            'overall_format_valid': False
        }
        
        # Check for required sections
        validation['has_cleanup_section'] = 'DB Cleanup Constant Variables' in data
        validation['has_signature_section'] = 'Signature List' in data
        
        # Check for define statements in cleanup section
        validation['has_define_statements'] = "define('" in data
        
        # Check for signature entries
        validation['has_signature_entries'] = 'Signature Name:' in data
        
        # Overall format is valid only if all checks pass
        validation['overall_format_valid'] = (
            validation['has_cleanup_section'] and
            validation['has_signature_section'] and
            validation['has_define_statements'] and
            validation['has_signature_entries']
        )
        
        return validation
    
    def save_classification(self, classification: Dict, output_file: str = None) -> str:
        """Save classification results to file"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Include input filename in the classification results filename for easier matching
            input_stem = self.input_file.stem
            output_file = f"classification_{input_stem}_{timestamp}.json"
        
        output_path = Path(output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(classification, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Classification results saved to: {output_path}")
        return str(output_path)
    
    def print_classification_summary(self, classification: Dict):
        """Print classification summary to console"""
        analysis = classification.get('analysis', {})
        
        print("\n" + "="*60)
        print("🔍 DATA CLASSIFICATION SUMMARY")
        print("="*60)
        print(f"📋 Format Compatibility: {analysis.get('format_compatibility', 'UNKNOWN')}")
        print(f"📊 Recognition Status: {analysis.get('recognition_status', 'UNKNOWN')}")
        print(f"🔧 Data Type: {analysis.get('data_type', 'UNKNOWN')}")
        print(f"🎯 YARA Compatibility: {analysis.get('yara_compatibility', 'UNKNOWN')}")
        print(f"📈 Conversion Readiness: {analysis.get('conversion_readiness', 0)}/10")
        print(f"✅ Can Proceed to YARA: {'YES' if analysis.get('can_proceed', False) else 'NO'}")
        print("="*60)
        
        if analysis.get('data_stats'):
            stats = analysis['data_stats']
            print(f"📋 Data Statistics:")
            print(f"   - Total Lines: {stats.get('total_lines', 0)}")
            print(f"   - Has Cleanup Section: {'YES' if stats.get('has_cleanup_section') else 'NO'}")
            print(f"   - Has Signature Section: {'YES' if stats.get('has_signature_section') else 'NO'}")
            print(f"   - Signature Count: {stats.get('signature_count', 0)}")
            print(f"   - Cleanup Constants: {stats.get('cleanup_constant_count', 0)}")
        
        # Show format validation details
        if analysis.get('format_validation'):
            validation = analysis['format_validation']
            print(f"\n🔍 Format Validation:")
            print(f"   - Has cleanup section: {'✅' if validation.get('has_cleanup_section') else '❌'}")
            print(f"   - Has signature section: {'✅' if validation.get('has_signature_section') else '❌'}")
            print(f"   - Has define statements: {'✅' if validation.get('has_define_statements') else '❌'}")
            print(f"   - Has signature entries: {'✅' if validation.get('has_signature_entries') else '❌'}")
            print(f"   - Overall format valid: {'✅' if validation.get('overall_format_valid') else '❌'}")
        
        if analysis.get('can_proceed', False):
            if analysis.get('is_binary_file', False):
                print("\n✅ Binary file detected - ready for LLM YARA generation!")
                print("   File will be processed directly by LLM to create YARA rule.")
            else:
                print("\n✅ Data is ready for YARA conversion!")
                print("   Format matches expected signature_patterns.txt structure.")
        else:
            print("\n❌ Data is NOT ready for YARA conversion.")
            if analysis.get('format_compatibility') == 'NO':
                print("   ❌ Format does not match expected signature_patterns.txt structure.")
                print("   💡 This format is not currently supported by the pipeline.")
                print("   📋 Expected format: signature_patterns.txt with cleanup constants and signature list")
            else:
                print("   Check the classification details for other issues.")
        
        print(f"\n📁 Classification results saved to: classification_{self.input_file.stem}_*.json")
        print(f"📋 Log file: classification.log")
    
    def extract_yara_rule_from_binary_analysis(self, classification: Dict) -> str:
        """Extract YARA rule from binary file analysis"""
        content = classification.get('classification_content', '')
        
        # Look for YARA rule in the response
        import re
        
        # Try to find YARA rule between rule and condition
        rule_pattern = r'rule\s+\w+\s*\{[^}]*condition[^}]*\}'
        rule_match = re.search(rule_pattern, content, re.DOTALL | re.IGNORECASE)
        
        if rule_match:
            return rule_match.group(0)
        
        # If no complete rule found, try to extract parts
        strings_pattern = r'strings:\s*\n([^}]*?)(?=\n\s*condition|\n\s*\})'
        strings_match = re.search(strings_pattern, content, re.DOTALL | re.IGNORECASE)
        
        condition_pattern = r'condition:\s*\n([^}]*?)(?=\n\s*\})'
        condition_match = re.search(condition_pattern, content, re.DOTALL | re.IGNORECASE)
        
        if strings_match and condition_match:
            # Replace dashes and spaces with underscores in rule name
            clean_stem = self.input_file.stem.replace('-', '_').replace(' ', '_')
            rule_name = f"rule binary_file_{clean_stem}"
            return f"{rule_name} {{\n    strings:\n{strings_match.group(1)}\n    condition:\n{condition_match.group(1)}\n}}"
        
        # Fallback: return a basic rule
        clean_stem = self.input_file.stem.replace('-', '_').replace(' ', '_')
        return f"rule binary_file_{clean_stem} {{\n    strings:\n        $s1 = \"binary_file_detected\"\n    condition:\n        $s1\n}}"

def main():
    parser = argparse.ArgumentParser(
        description="Classify JSON data structure for YARA conversion suitability"
    )
    parser.add_argument(
        "json_file", 
        help="Path to JSON file to classify"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for classification results"
    )
    parser.add_argument(
        "--custom-prompt", "-p",
        help="Custom optimized prompt to use instead of default prompts"
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
        # Initialize classifier
        classifier = DataClassifier(args.json_file)
        
        # Load data
        data = classifier.load_input_data()
        
        # Classify data with optional custom prompt
        classification = classifier.classify_data(data, args.custom_prompt)
        
        # Save results
        output_file = classifier.save_classification(classification, args.output)
        
        # Print summary
        classifier.print_classification_summary(classification)
        
        # Exit with appropriate code
        analysis = classification.get('analysis', {})
        if analysis.get('can_proceed', False):
            sys.exit(0)  # Success - can proceed
        else:
            sys.exit(1)  # Failure - cannot proceed
        
    except Exception as e:
        logger.error(f"💥 Classification failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
