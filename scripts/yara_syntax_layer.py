#!/usr/bin/env python3
"""
YARA Syntax Validation Layer
Runs immediately after LLM rule generation to validate and fix syntax before adding to YARA file
"""

import os
import sys
import json
import logging
import requests
import re
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('yara_syntax_layer.log')
    ]
)
logger = logging.getLogger(__name__)

class YaraSyntaxLayer:
    """Dedicated YARA syntax validation layer that runs after LLM rule generation"""
    
    def __init__(self):
        self.jwt_token = os.getenv("JWT")
        self.api_url = os.getenv("API_URL")
        
        if not self.jwt_token:
            raise ValueError("JWT token not found in environment variables")
        if not self.api_url:
            raise ValueError("API_URL not found in environment variables")
        
        logger.info(f"🔧 Initialized YARA Syntax Layer with API: {self.api_url}")
    
    def create_syntax_validation_prompt(self, rule_content: str, rule_name: str = None) -> str:
        """Create a prompt for YARA syntax validation and correction"""
        
        prompt = f"""You are a YARA rule syntax expert. Your ONLY job is to validate and correct YARA syntax errors.

YARA RULE TO VALIDATE:
{rule_content}

YARA SYNTAX RULES AND BEST PRACTICES:

1. STRINGS SECTION:
   - All strings must be defined before use in conditions
   - String names must start with $ and be valid identifiers
   - Use 'ascii', 'wide', 'nocase' modifiers as needed
   - Hex strings use format: $hex_string = {{ 01 02 03 }} or {{ 01 02 03 ?? 05 }}
   - Regular expressions: $regex = /pattern/ ascii

2. CONDITION SECTION:
   - Use 'and', 'or', 'not' for logical operations
   - Use 'of' for counting: '2 of ($string1, $string2, $string3)'
   - Use 'for any' for loops: 'for any i in (1..#a) : ( @a[i] < 10 )'
   - Use 'at' for position: 'at 100' or 'at entrypoint'
   - Use 'in' for range: 'in (0..100)'
   - Use parentheses for complex expressions: (a and b) or (c and d)

3. FILE TYPE DETECTION:
   - NEVER use 'filetype' - it doesn't exist in YARA
   - Use file signatures: '<?php' for PHP, 'MZ' for PE, 'ELF' for Linux
   - Use magic bytes: 'uint16(0) == 0x5A4D' for PE files
   - Use file extensions: 'uint32(0) == 0x04034B50' for ZIP

4. COMMON SYNTAX PATTERNS:
   - Meta section: meta: description = "text", author = "name"
   - Strings section: strings: $name = "value" ascii
   - Condition section: condition: expression
   - Use semicolons to separate meta fields

5. PHP FILE DETECTION EXAMPLES:
   - PHP header: '$php_header = "<?php" ascii'
   - PHP short tag: '$php_short = "<?=" ascii'
   - Condition: '($php_header or $php_short) and ...'

6. AVOID THESE COMMON MISTAKES:
   - 'filetype == "php"' → Use '($php_header or $php_short)'
   - Undefined string references in conditions
   - Missing parentheses in complex expressions
   - Incorrect 'of' syntax: '2 of $string' → '2 of ($string1, $string2)'
   - Missing semicolons in meta section
   - Unclosed quotes or brackets

7. VALIDATION CHECKLIST:
   - [ ] All strings referenced in conditions are defined
   - [ ] No 'filetype' identifier used
   - [ ] Proper logical operators (and, or, not)
   - [ ] Correct 'of' syntax for counting
   - [ ] Balanced parentheses and brackets
   - [ ] Valid string modifiers (ascii, wide, nocase)
   - [ ] Proper meta section formatting

TASK: 
1. Analyze the YARA rule for syntax errors
2. Fix any syntax issues found
3. Ensure the rule follows YARA best practices
4. Return ONLY the corrected YARA rule, nothing else

The rule must be syntactically valid and ready to use in a YARA file."""

        return prompt
    
    def call_gocaas_for_syntax_validation(self, prompt: str) -> str:
        """Call Gocaas API for YARA syntax validation and correction"""
        try:
            headers = {
                "Authorization": f"Bearer {self.jwt_token}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "isPrivate": True,
                "provider": "anthropic_chat",
                "providerOptions": {
                    "model": "claude-3-5-haiku-20241022-v1:0",
                    "max_tokens": 2048,
                    "temperature": 0.1  # Low temperature for consistent syntax
                },
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a YARA rule syntax expert. Your ONLY job is to validate and fix YARA syntax errors. Return ONLY the corrected YARA rule, nothing else."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
            
            logger.info("🤖 Calling Gocaas API for YARA syntax validation...")
            
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'choices' in result and len(result['choices']) > 0:
                    corrected_rule = result['choices'][0]['message']['content'].strip()
                    logger.info("✅ Gocaas syntax validation successful")
                    return corrected_rule
                else:
                    raise ValueError("Unexpected Gocaas response format")
            else:
                logger.error(f"❌ Gocaas API call failed: {response.status_code} - {response.text}")
                raise Exception(f"Gocaas API call failed with status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Network error calling Gocaas: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Error calling Gocaas: {e}")
            raise
    
    def extract_yara_rule_from_response(self, response: str) -> str:
        """Extract the YARA rule from the Gocaas response"""
        # Look for rule block
        lines = response.split('\n')
        rule_lines = []
        in_rule = False
        
        for line in lines:
            line = line.strip()
            
            if line.startswith('rule '):
                in_rule = True
                rule_lines.append(line)
            elif in_rule:
                rule_lines.append(line)
                if line == '}':
                    break
        
        if not rule_lines:
            logger.warning("⚠️  No YARA rule found in Gocaas response")
            return response
        
        return '\n'.join(rule_lines)
    
    def validate_single_rule(self, rule_content: str, rule_name: str = None) -> Dict:
        """Validate and correct a single YARA rule"""
        try:
            logger.info(f"🔍 Validating YARA rule: {rule_name or 'unnamed'}")
            
            # Create syntax validation prompt
            prompt = self.create_syntax_validation_prompt(rule_content, rule_name)
            
            # Get Gocaas validation
            gocaas_response = self.call_gocaas_for_syntax_validation(prompt)
            
            # Extract corrected rule from response
            corrected_rule = self.extract_yara_rule_from_response(gocaas_response)
            
            # Check if the rule was actually corrected
            was_corrected = rule_content.strip() != corrected_rule.strip()
            
            return {
                'rule_name': rule_name,
                'original_rule': rule_content,
                'corrected_rule': corrected_rule,
                'was_corrected': was_corrected,
                'gocaas_response': gocaas_response,
                'timestamp': datetime.now().isoformat(),
                'validation_layer': 'yara_syntax_layer.py'
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to validate rule {rule_name or 'unnamed'}: {e}")
            return {
                'rule_name': rule_name,
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'validation_layer': 'yara_syntax_layer.py'
            }
    
    def validate_llm_generated_rules(self, rules: List[Dict]) -> List[Dict]:
        """Validate all LLM-generated YARA rules through the syntax layer"""
        try:
            logger.info(f"🔍 Validating {len(rules)} LLM-generated rules through syntax layer...")
            
            validated_rules = []
            correction_count = 0
            
            for rule in rules:
                rule_name = rule.get('name', 'unnamed')
                rule_content = rule.get('content', '')
                
                if not rule_content:
                    logger.warning(f"⚠️  Rule {rule_name} has no content, skipping")
                    validated_rules.append(rule)
                    continue
                
                # Validate through syntax layer
                validation_result = self.validate_single_rule(rule_content, rule_name)
                
                if 'error' in validation_result:
                    logger.warning(f"⚠️  Rule {rule_name} validation failed: {validation_result['error']}")
                    # Keep original rule if validation fails
                    validated_rules.append(rule)
                else:
                    if validation_result['was_corrected']:
                        logger.info(f"✅ Rule {rule_name} syntax corrected")
                        correction_count += 1
                        # Update rule with corrected content
                        rule['content'] = validation_result['corrected_rule']
                        rule['syntax_validated'] = True
                        rule['correction_details'] = validation_result
                    else:
                        logger.info(f"✅ Rule {rule_name} syntax already valid")
                        rule['syntax_validated'] = True
                        rule['correction_details'] = validation_result
                    
                    validated_rules.append(rule)
            
            logger.info(f"✅ Syntax validation complete: {correction_count} rules corrected")
            return validated_rules
            
        except Exception as e:
            logger.error(f"❌ Failed to validate rules through syntax layer: {e}")
            return rules  # Return original rules if validation fails
    
    def save_validation_results(self, results: List[Dict], output_file: str = None) -> Path:
        """Save syntax validation results to file"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"yara_syntax_layer_{timestamp}.json"
        
        output_path = Path(output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Syntax validation results saved to: {output_path}")
        return output_path
    
    def print_validation_summary(self, results: List[Dict]):
        """Print a summary of syntax validation results"""
        print("\n" + "="*70)
        print("🔍 YARA SYNTAX LAYER VALIDATION SUMMARY")
        print("="*70)
        
        total_rules = len(results)
        validated_rules = sum(1 for r in results if r.get('syntax_validated', False))
        corrected_rules = sum(1 for r in results if r.get('correction_details', {}).get('was_corrected', False))
        failed_validations = sum(1 for r in results if 'error' in r.get('correction_details', {}))
        
        print(f"📊 Total Rules Processed: {total_rules}")
        print(f"✅ Successfully Validated: {validated_rules}")
        print(f"🔧 Rules Corrected: {corrected_rules}")
        print(f"❌ Validation Failures: {failed_validations}")
        print(f"⏰ Timestamp: {datetime.now().isoformat()}")
        
        if corrected_rules > 0:
            print(f"\n🔧 Corrected Rules:")
            print("-" * 50)
            for rule in results:
                if rule.get('correction_details', {}).get('was_corrected', False):
                    rule_name = rule.get('name', 'unnamed')
                    print(f"✅ {rule_name}: Syntax corrected")
        
        if failed_validations > 0:
            print(f"\n❌ Failed Validations:")
            print("-" * 50)
            for rule in results:
                if 'error' in rule.get('correction_details', {}):
                    rule_name = rule.get('name', 'unnamed')
                    error = rule['correction_details']['error']
                    print(f"❌ {rule_name}: {error}")

def main():
    parser = argparse.ArgumentParser(
        description="YARA Syntax Validation Layer - validates LLM-generated rules before adding to YARA file"
    )
    parser.add_argument(
        "rules_file",
        help="Path to JSON file containing LLM-generated YARA rules"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for validation results"
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
        # Initialize syntax layer
        syntax_layer = YaraSyntaxLayer()
        
        # Load LLM-generated rules
        with open(args.rules_file, 'r', encoding='utf-8') as f:
            rules = json.load(f)
        
        # Validate rules through syntax layer
        validated_rules = syntax_layer.validate_llm_generated_rules(rules)
        
        # Save results
        output_file = syntax_layer.save_validation_results(validated_rules, args.output)
        
        # Print summary
        syntax_layer.print_validation_summary(validated_rules)
        
        # Exit with appropriate code
        failed_count = sum(1 for r in validated_rules if 'error' in r.get('correction_details', {}))
        if failed_count == 0:
            print("\n🎉 All rules successfully validated through syntax layer!")
            exit(0)
        else:
            print(f"\n⚠️  {failed_count} rules had validation failures.")
            exit(1)
        
    except Exception as e:
        logger.error(f"💥 Syntax layer failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
