#!/usr/bin/env python3
"""
YARA Rule Revision Script
Automatically sends validation errors to LLM for rule correction
"""

import os
import sys
import json
import argparse
import logging
import subprocess
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
        logging.FileHandler('yara_revision.log')
    ]
)
logger = logging.getLogger(__name__)

class YaraRuleRevisor:
    """Automatically revise YARA rules using LLM feedback"""
    
    def __init__(self):
        self.jwt_token = os.getenv("JWT")
        self.api_url = os.getenv("API_URL")
        
        if not self.jwt_token:
            raise ValueError("JWT token not found in environment variables")
        if not self.api_url:
            raise ValueError("API_URL not found in environment variables")
        
        logger.info(f"🔧 Initialized YARA Rule Revisor with API: {self.api_url}")
    
    def load_validation_results(self, validation_file: Path) -> Dict:
        """Load validation results from file"""
        try:
            with open(validation_file, 'r', encoding='utf-8') as f:
                results = json.load(f)
            logger.info(f"📋 Loaded validation results from: {validation_file}")
            return results
        except Exception as e:
            logger.error(f"❌ Failed to load validation results: {e}")
            raise
    
    def load_yara_rules(self, yara_file: Path) -> str:
        """Load the current YARA rules file"""
        try:
            with open(yara_file, 'r', encoding='utf-8') as f:
                content = f.read()
            logger.info(f"📋 Loaded YARA rules from: {yara_file}")
            return content
        except Exception as e:
            logger.error(f"❌ Failed to load YARA rules: {e}")
            raise
    
    def create_revision_prompt(self, rule_name: str, rule_content: str, errors: List[str], yara_file_content: str) -> str:
        """Create a prompt for the LLM to revise the YARA rule"""
        
        # Find the specific rule in the file
        rule_start = yara_file_content.find(f"rule {rule_name}")
        if rule_start == -1:
            rule_start = 0
        
        # Extract a bit more context around the rule
        context_start = max(0, rule_start - 200)
        context_end = min(len(yara_file_content), rule_start + len(rule_content) + 200)
        rule_context = yara_file_content[context_start:context_end]
        
        prompt = f"""You are a YARA rule expert. The following YARA rule has syntax errors that need to be fixed.

CURRENT RULE:
{rule_content}

ERRORS FOUND:
{chr(10).join(f"- {error}" for error in errors)}

CONTEXT FROM FILE:
{rule_context}

TASK: Fix the YARA rule to resolve all syntax errors. Ensure:
1. All identifiers used in the condition are properly defined in the strings section
2. Proper YARA syntax is maintained
3. The rule logic remains intact
4. Use proper PHP file detection (<?php or <?=) instead of invalid identifiers like 'filetype'

IMPORTANT RULES:
- NEVER use 'filetype' identifier - it doesn't exist in YARA
- Use '<?php' or '<?=' to detect PHP files
- All strings referenced in conditions must be defined
- Maintain proper YARA syntax structure

Return ONLY the corrected YARA rule, nothing else. The rule should be syntactically valid and ready to use."""

        return prompt
    
    def call_llm_for_revision(self, prompt: str) -> str:
        """Call the LLM API to get revised YARA rule"""
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
                    "temperature": 0.1
                },
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }
            
            logger.info("🤖 Calling LLM for YARA rule revision...")
            
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
                    logger.info("✅ LLM revision successful")
                    return revised_rule
                else:
                    raise ValueError("Unexpected LLM response format")
            else:
                logger.error(f"❌ LLM API call failed: {response.status_code} - {response.text}")
                raise Exception(f"LLM API call failed with status {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Network error calling LLM: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Error calling LLM: {e}")
            raise
    
    def extract_yara_rule_from_response(self, response: str) -> str:
        """Extract the YARA rule from the LLM response"""
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
            logger.warning("⚠️  No YARA rule found in LLM response")
            return response
        
        return '\n'.join(rule_lines)
    
    def validate_revised_rule(self, revised_rule: str) -> Dict:
        """Validate the revised rule using YARA syntax validator"""
        try:
            # Create temporary file with revised rule
            temp_file = Path(f"temp_revised_rule.yar")
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(revised_rule)
            
            # Run YARA syntax validation
            validator_cmd = [
                sys.executable,
                "scripts/yara_syntax_validator.py",
                str(temp_file)
            ]
            
            logger.info("🔍 Validating revised rule...")
            
            result = subprocess.run(
                validator_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Clean up temp file
            temp_file.unlink()
            
            if result.returncode == 0:
                return {
                    'valid': True,
                    'errors': [],
                    'message': 'Revised rule is syntactically valid'
                }
            else:
                # Parse validation errors
                try:
                    # Look for validation results in the output
                    for line in result.stdout.split('\n'):
                        if 'yara_validation_' in line and '.json' in line:
                            validation_file = line.split()[-1]
                            with open(validation_file, 'r') as f:
                                validation_data = json.load(f)
                            return {
                                'valid': validation_data.get('valid', False),
                                'errors': validation_data.get('rules', [{}])[0].get('errors', []),
                                'message': 'Revised rule still has syntax errors'
                            }
                except:
                    pass
                
                return {
                    'valid': False,
                    'errors': [result.stderr.strip() if result.stderr else 'Unknown validation error'],
                    'message': 'Revised rule validation failed'
                }
                
        except Exception as e:
            logger.error(f"❌ Error validating revised rule: {e}")
            return {
                'valid': False,
                'errors': [str(e)],
                'message': 'Validation process failed'
            }
    
    def revise_rule(self, rule_name: str, rule_content: str, errors: List[str], yara_file_content: str) -> Dict:
        """Revise a single YARA rule using LLM feedback"""
        try:
            logger.info(f"🔧 Revising rule: {rule_name}")
            
            # Create revision prompt
            prompt = self.create_revision_prompt(rule_name, rule_content, errors, yara_file_content)
            
            # Get LLM revision
            llm_response = self.call_llm_for_revision(prompt)
            
            # Extract YARA rule from response
            revised_rule = self.extract_yara_rule_from_response(llm_response)
            
            # Validate the revised rule
            validation_result = self.validate_revised_rule(revised_rule)
            
            return {
                'rule_name': rule_name,
                'original_rule': rule_content,
                'revised_rule': revised_rule,
                'llm_response': llm_response,
                'validation_result': validation_result,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to revise rule {rule_name}: {e}")
            return {
                'rule_name': rule_name,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def revise_all_invalid_rules(self, validation_file: Path, yara_file: Path) -> Dict:
        """Revise all invalid YARA rules"""
        try:
            # Load validation results and YARA rules
            validation_results = self.load_validation_results(validation_file)
            yara_content = self.load_yara_rules(yara_file)
            
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
                    # Find rule end
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
                
                revision_result = self.revise_rule(rule_name, full_rule_content, errors, yara_content)
                revision_results.append(revision_result)
            
            return {
                'status': 'success',
                'total_rules': len(invalid_rules),
                'revision_results': revision_results,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Failed to revise rules: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def save_revision_results(self, results: Dict, output_file: str = None) -> Path:
        """Save revision results to file"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"yara_revision_{timestamp}.json"
        
        output_path = Path(output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Revision results saved to: {output_path}")
        return output_path
    
    def print_revision_summary(self, results: Dict):
        """Print a summary of revision results"""
        print("\n" + "="*70)
        print("🔧 YARA RULE REVISION SUMMARY")
        print("="*70)
        
        if results['status'] == 'error':
            print(f"❌ Revision failed: {results['error']}")
            return
        
        if 'message' in results and 'No rules need revision' in results['message']:
            print("✅ No rules need revision")
            return
        
        total_rules = results.get('total_rules', 0)
        revision_results = results.get('revision_results', [])
        
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
                validation = result['validation_result']
                if validation['valid']:
                    print(f"✅ SUCCESS | {rule_name}: Rule is now valid")
                    successful_revisions += 1
                else:
                    print(f"⚠️  PARTIAL | {rule_name}: Still has {len(validation['errors'])} error(s)")
                    failed_revisions += 1
                    for error in validation['errors']:
                        print(f"    ❌ {error}")
        
        print(f"\n📊 Summary:")
        print(f"   ✅ Successful: {successful_revisions}")
        print(f"   ⚠️  Partial: {failed_revisions}")
        print(f"   📈 Success Rate: {(successful_revisions/total_rules*100):.1f}%" if total_rules > 0 else "0%")

def main():
    parser = argparse.ArgumentParser(
        description="Automatically revise YARA rules using LLM feedback"
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
        # Initialize revisor
        revisor = YaraRuleRevisor()
        
        # Revise invalid rules
        results = revisor.revise_all_invalid_rules(
            Path(args.validation_file),
            Path(args.yara_file)
        )
        
        # Save results
        output_file = revisor.save_revision_results(results, args.output)
        
        # Print summary
        revisor.print_revision_summary(results)
        
        # Exit with appropriate code
        if results['status'] == 'success':
            if 'No rules need revision' in results.get('message', ''):
                print("\n🎉 All YARA rules are valid!")
                exit(0)
            else:
                successful = sum(1 for r in results.get('revision_results', []) 
                               if 'error' not in r and r.get('validation_result', {}).get('valid', False))
                total = results.get('total_rules', 0)
                if successful == total:
                    print("\n🎉 All revised rules are now valid!")
                    exit(0)
                else:
                    print(f"\n⚠️  {successful}/{total} rules successfully revised.")
                    exit(1)
        else:
            print(f"\n❌ Revision failed: {results['error']}")
            exit(1)
        
    except Exception as e:
        logger.error(f"💥 Revision failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
