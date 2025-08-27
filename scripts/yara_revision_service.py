#!/usr/bin/env python3
"""
YARA Revision Service
Specialized service for revising YARA rules with comprehensive syntax knowledge
"""

import os
import sys
import json
import argparse
import logging
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('yara_revision_service.log')
    ]
)
logger = logging.getLogger(__name__)

class YaraRevisionService:
    """Specialized service for YARA rule revision with comprehensive syntax knowledge"""
    
    def __init__(self):
        self.jwt_token = os.getenv("JWT")
        self.api_url = os.getenv("API_URL")
        
        if not self.jwt_token:
            raise ValueError("JWT token not found in environment variables")
        if not self.api_url:
            raise ValueError("API_URL not found in environment variables")
        
        logger.info(f"🔧 Initialized YARA Revision Service with API: {self.api_url}")
    
    def create_specialized_revision_prompt(self, rule_name: str, rule_content: str, 
                                         errors: List[str], yara_file_content: str) -> str:
        """Create a specialized prompt for YARA rule revision with comprehensive syntax knowledge"""
        
        # Find the specific rule in the file for context
        rule_start = yara_file_content.find(f"rule {rule_name}")
        if rule_start == -1:
            rule_start = 0
        
        # Extract context around the rule
        context_start = max(0, rule_start - 300)
        context_end = min(len(yara_file_content), rule_start + len(rule_content) + 300)
        rule_context = yara_file_content[context_start:context_end]
        
        prompt = f"""You are a YARA rule expert specializing in syntax correction and optimization. Your ONLY job is to fix YARA syntax errors.

CURRENT RULE WITH ERRORS:
{rule_content}

VALIDATION ERRORS FOUND:
{chr(10).join(f"- {error}" for error in errors)}

CONTEXT FROM FILE:
{rule_context}

YARA SYNTAX RULES AND BEST PRACTICES:
1. STRINGS SECTION:
   - All strings must be defined before use in conditions
   - String names must start with $ and be valid identifiers
   - Use 'ascii', 'wide', 'nocase' modifiers as needed
   - Hex strings use format: $hex_string = {{ 01 02 03 }} or {{ 01 02 03 ?? 05 }}

2. CONDITION SECTION:
   - Use 'and', 'or', 'not' for logical operations
   - Use 'of' for counting: '2 of ($string1, $string2, $string3)'
   - Use 'for any' for loops: 'for any i in (1..#a) : ( @a[i] < 10 )'
   - Use 'at' for position: 'at 100' or 'at entrypoint'
   - Use 'in' for range: 'in (0..100)'

3. FILE TYPE DETECTION:
   - NEVER use 'filetype' - it doesn't exist in YARA
   - Use file signatures: '<?php' for PHP, 'MZ' for PE, 'ELF' for Linux
   - Use magic bytes: 'uint16(0) == 0x5A4D' for PE files
   - Use file extensions: 'uint32(0) == 0x04034B50' for ZIP

4. COMMON SYNTAX PATTERNS:
   - Meta section: meta: description = "text", author = "name"
   - Strings section: strings: $name = "value" ascii
   - Condition section: condition: expression
   - Use parentheses for complex expressions: (a and b) or (c and d)

5. PHP FILE DETECTION EXAMPLES:
   - PHP header: '$php_header = "<?php" ascii'
   - PHP short tag: '$php_short = "<?=" ascii'
   - Condition: '($php_header or $php_short) and ...'

6. AVOID THESE COMMON MISTAKES:
   - 'filetype == "php"' → Use '($php_header or $php_short)'
   - Undefined string references in conditions
   - Missing parentheses in complex expressions
   - Incorrect 'of' syntax: '2 of $string' → '2 of ($string1, $string2)'

TASK: Fix the YARA rule to resolve ALL syntax errors. Ensure:
1. All strings referenced in conditions are properly defined
2. Use correct file type detection methods
3. Maintain proper YARA syntax structure
4. Keep the rule logic and detection capabilities intact
5. Follow YARA best practices

Return ONLY the corrected YARA rule, nothing else. The rule must be syntactically valid and ready to use."""

        return prompt
    
    def call_gocaas_for_revision(self, prompt: str) -> str:
        """Call Gocaas API specifically for YARA rule revision"""
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
                        "content": "You are a YARA rule syntax expert. Your ONLY job is to fix YARA syntax errors. Return ONLY the corrected YARA rule, nothing else."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
            
            logger.info("🤖 Calling Gocaas API for specialized YARA rule revision...")
            
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=60
            )
            
            if response.status_code == 200:
                result = response.json()
                if 'choices' in result and len(result['choices']) > 0:
                    revised_rule = result['choices'][0]['message']['content'].strip()
                    logger.info("✅ Gocaas revision successful")
                    return revised_rule
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
    
    def revise_yara_rule(self, rule_name: str, rule_content: str, 
                         errors: List[str], yara_file_content: str) -> Dict:
        """Revise a single YARA rule using specialized YARA knowledge"""
        try:
            logger.info(f"🔧 Revising YARA rule: {rule_name}")
            
            # Create specialized revision prompt
            prompt = self.create_specialized_revision_prompt(
                rule_name, rule_content, errors, yara_file_content
            )
            
            # Get Gocaas revision
            gocaas_response = self.call_gocaas_for_revision(prompt)
            
            # Extract YARA rule from response
            revised_rule = self.extract_yara_rule_from_response(gocaas_response)
            
            return {
                'rule_name': rule_name,
                'original_rule': rule_content,
                'revised_rule': revised_rule,
                'gocaas_response': gocaas_response,
                'errors_fixed': errors,
                'timestamp': datetime.now().isoformat(),
                'revision_service': 'yara_revision_service.py'
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to revise rule {rule_name}: {e}")
            return {
                'rule_name': rule_name,
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'revision_service': 'yara_revision_service.py'
            }
    
    def revise_all_invalid_rules(self, validation_file: Path, yara_file: Path) -> Dict:
        """Revise all invalid YARA rules using specialized service"""
        try:
            # Load validation results and YARA rules
            with open(validation_file, 'r', encoding='utf-8') as f:
                validation_results = json.load(f)
            
            with open(yara_file, 'r', encoding='utf-8') as f:
                yara_content = f.read()
            
            if not validation_results.get('rules'):
                logger.info("✅ No rules to revise - all rules are valid")
                return {'status': 'success', 'message': 'No rules need revision'}
            
            # Find invalid rules
            invalid_rules = []
            for rule in validation_results['rules']:
                if not rule.get('valid', False):
                    invalid_rules.append(rule)
            
            if not invalid_rules:
                logger.info("✅ No invalid rules found")
                return {'status': 'success', 'message': 'No rules need revision'}
            
            logger.info(f"🔧 Found {len(invalid_rules)} invalid rules to revise")
            
            # Revise each invalid rule
            revision_results = []
            for rule in invalid_rules:
                rule_name = rule['name']
                rule_content = rule['content_preview']
                errors = rule.get('errors', [])
                
                # Extract full rule content from YARA file
                rule_start = yara_content.find(f"rule {rule_name}")
                if rule_start != -1:
                    # Find rule end by counting braces
                    brace_count = 0
                    rule_end = rule_start
                    for i in range(rule_start, len(yara_content)):
                        if yara_content[i] == '{':
                            brace_count += 1
                        elif yara_content[i] == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                rule_end = i + 1
                                break
                    
                    full_rule_content = yara_content[rule_start:rule_end]
                else:
                    full_rule_content = rule_content
                
                revision_result = self.revise_yara_rule(
                    rule_name, full_rule_content, errors, yara_content
                )
                revision_results.append(revision_result)
            
            return {
                'status': 'success',
                'total_rules': len(invalid_rules),
                'revision_results': revision_results,
                'timestamp': datetime.now().isoformat(),
                'service': 'yara_revision_service.py'
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to revise rules: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'service': 'yara_revision_service.py'
            }
    
    def save_revision_results(self, results: Dict, output_file: str = None) -> Path:
        """Save revision results to file"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"yara_revision_service_{timestamp}.json"
        
        output_path = Path(output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Revision results saved to: {output_path}")
        return output_path
    
    def print_revision_summary(self, results: Dict):
        """Print a summary of revision results"""
        print("\n" + "="*70)
        print("🔧 YARA REVISION SERVICE SUMMARY")
        print("="*70)
        
        if results['status'] == 'error':
            print(f"❌ Revision failed: {results['error']}")
            return
        
        if 'message' in results and 'No rules need revision' in results['message']:
            print("✅ No rules need revision")
            return
        
        total_rules = results.get('total_rules', 0)
        revision_results = results.get('revision_results', [])
        service = results.get('service', 'Unknown')
        
        print(f"🔧 Service: {service}")
        print(f"📊 Total rules revised: {total_rules}")
        print(f"⏰ Timestamp: {results['timestamp']}")
        
        print(f"\n📋 Revision Results:")
        print("-" * 50)
        
        successful_revisions = 0
        failed_revisions = 0
        
        for result in revision_results:
            rule_name = result['rule_name']
            
            if 'error' in result:
                print(f"❌ FAILED | {rule_name}: {result['error']}")
                failed_revisions += 1
            else:
                print(f"✅ SUCCESS | {rule_name}: Rule revised successfully")
                print(f"    📝 Errors fixed: {len(result.get('errors_fixed', []))}")
                successful_revisions += 1
        
        print(f"\n📊 Summary:")
        print(f"   ✅ Successful: {successful_revisions}")
        print(f"   ❌ Failed: {failed_revisions}")
        print(f"   📈 Success Rate: {(successful_revisions/total_rules*100):.1f}%" if total_rules > 0 else "0%")

def main():
    parser = argparse.ArgumentParser(
        description="Specialized YARA rule revision service using Gocaas API"
    )
    parser.add_argument(
        "validation_file",
        help="Path to validation results JSON file"
    )
    parser.add_argument(
        "yara_file",
        help="Path to YARA rules file to revise"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for revision results"
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
        # Initialize revision service
        service = YaraRevisionService()
        
        # Revise invalid rules
        results = service.revise_all_invalid_rules(
            Path(args.validation_file),
            Path(args.yara_file)
        )
        
        # Save results
        output_file = service.save_revision_results(results, args.output)
        
        # Print summary
        service.print_revision_summary(results)
        
        # Exit with appropriate code
        if results['status'] == 'success':
            if 'No rules need revision' in results.get('message', ''):
                print("\n🎉 All YARA rules are valid!")
                exit(0)
            else:
                successful = sum(1 for r in results.get('revision_results', []) 
                               if 'error' not in r)
                total = results.get('total_rules', 0)
                if successful == total:
                    print("\n🎉 All rules successfully revised!")
                    exit(0)
                else:
                    print(f"\n⚠️  {successful}/{total} rules successfully revised.")
                    exit(1)
        else:
            print(f"\n❌ Revision failed: {results['error']}")
            exit(1)
        
    except Exception as e:
        logger.error(f"💥 Revision service failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
