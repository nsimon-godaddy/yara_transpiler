#!/usr/bin/env python3
"""
YARA LLM Validation Layer
Uses Gocaas API to validate generated YARA rules for quality, correctness, and effectiveness
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dotenv import load_dotenv
import requests
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('validation.log')
    ]
)
logger = logging.getLogger(__name__)

class YaraValidator:
    """YARA rule validator using Gocaas API"""
    
    def __init__(self, yara_file: str, json_file: str = None):
        # Load environment variables
        load_dotenv()
        
        self.jwt = os.getenv("JWT")
        self.api_url = os.getenv("API_URL")
        
        if not self.jwt or not self.api_url:
            raise ValueError("JWT and API_URL environment variables must be set")
        
        self.yara_file = Path(yara_file)
        self.json_file = Path(json_file) if json_file else None
        
        # API configuration
        self.api_config = {
            "isPrivate": True,
            "provider": "anthropic_chat",
            "providerOptions": {
                "model": "claude-3-5-haiku-20241022-v1:0",
                "max_tokens": 4096
            }
        }
        
        self.headers = {
            "Authorization": f"sso-jwt {self.jwt}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
    
    def parse_yara_rules(self) -> List[Dict]:
        """Parse YARA file and extract individual rules"""
        if not self.yara_file.exists():
            raise FileNotFoundError(f"YARA file not found: {self.yara_file}")
        
        with open(self.yara_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Split into individual rules
        rules = []
        current_rule = ""
        rule_name = ""
        
        for line in content.split('\n'):
            if line.strip().startswith('rule '):
                # Save previous rule if exists
                if current_rule and rule_name:
                    rules.append({
                        'name': rule_name,
                        'content': current_rule.strip(),
                        'line_count': current_rule.count('\n') + 1
                    })
                
                # Start new rule
                rule_name = line.strip().split()[1]  # Extract rule name
                current_rule = line + '\n'
            else:
                current_rule += line + '\n'
        
        # Add the last rule
        if current_rule and rule_name:
            rules.append({
                'name': rule_name,
                'content': current_rule.strip(),
                'line_count': current_rule.count('\n') + 1
            })
        
        logger.info(f"📋 Parsed {len(rules)} YARA rules from {self.yara_file}")
        return rules
    
    def get_validation_prompt(self, rule: Dict, context: Dict = None) -> List[Dict]:
        """Generate validation prompt for a YARA rule"""
        
        system_prompt = """Task: Validate this YARA rule for correctness, effectiveness, and best practices.

Context: Analyze syntax, pattern effectiveness, performance, and security implications.

Constraints: Check for syntax errors, false positive risks, and optimization opportunities.

Output format: Return structured validation report with specific recommendations."""

        # Build context information if available
        context_info = ""
        if context and self.json_file and self.json_file.exists():
            try:
                with open(self.json_file, 'r') as f:
                    json_data = json.load(f)
                
                # Find matching signature
                for sig in json_data.get('signatures', []):
                    if sig.get('name', '').replace('.', '_') in rule['name']:
                        context_info = f"""
ORIGINAL SIGNATURE CONTEXT:
- Name: {sig.get('name', 'N/A')}
- Cleanup Pattern: {sig.get('cleanup_pattern', 'N/A')}
- Triggers: {sig.get('triggers', [])}
- Full Chain: {sig.get('full_chain', [])}
"""
                        break
            except Exception as e:
                logger.warning(f"Could not load context: {e}")
        
        user_prompt = f"""YARA RULE TO VALIDATE:
{rule['content']}

{context_info}

Validate this YARA rule."""

        return [
            {"from": "system", "content": system_prompt},
            {"from": "user", "content": user_prompt}
        ]
    
    def validate_rule(self, rule: Dict, context: Dict = None) -> Dict:
        """Validate a single YARA rule using Gocaas API"""
        try:
            prompts = self.get_validation_prompt(rule, context)
            
            payload = {
                "prompts": prompts,
                **self.api_config
            }
            
            logger.info(f"🔍 Validating rule: {rule['name']}")
            
            response = requests.post(
                self.api_url, 
                headers=self.headers, 
                json=payload,
                timeout=60
            )
            
            if response.status_code in [200, 201]:  # Both 200 and 201 indicate success
                result = response.json()
                validation_content = result.get("data", {}).get("value", {}).get("content", "")
                
                return {
                    'rule_name': rule['name'],
                    'status': 'validated',
                    'validation_content': validation_content,
                    'timestamp': datetime.now().isoformat(),
                    'api_response': result
                }
            else:
                logger.error(f"API request failed for {rule['name']}: {response.status_code}")
                return {
                    'rule_name': rule['name'],
                    'status': 'api_error',
                    'error': f"HTTP {response.status_code}: {response.text}",
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            logger.error(f"Validation failed for {rule['name']}: {e}")
            return {
                'rule_name': rule['name'],
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def validate_all_rules(self, max_rules: Optional[int] = None, 
                          sample_size: Optional[int] = None) -> Dict:
        """Validate all YARA rules or a sample"""
        rules = self.parse_yara_rules()
        
        if max_rules and len(rules) > max_rules:
            logger.warning(f"⚠️  Limiting validation to {max_rules} rules (total: {len(rules)})")
            rules = rules[:max_rules]
        
        if sample_size and len(rules) > sample_size:
            import random
            rules = random.sample(rules, sample_size)
            logger.info(f"🎲 Randomly sampling {sample_size} rules for validation")
        
        logger.info(f"🚀 Starting validation of {len(rules)} rules...")
        
        results = []
        context = self._load_context() if self.json_file else None
        
        for i, rule in enumerate(rules, 1):
            logger.info(f"📊 Progress: {i}/{len(rules)} - {rule['name']}")
            result = self.validate_rule(rule, context)
            results.append(result)
            
            # Small delay to avoid overwhelming the API
            import time
            time.sleep(0.5)
        
        # Generate summary
        summary = self._generate_summary(results)
        
        return {
            'validation_summary': summary,
            'rule_results': results,
            'total_rules': len(rules),
            'validation_timestamp': datetime.now().isoformat()
        }
    
    def _load_context(self) -> Dict:
        """Load context from JSON file if available"""
        if not self.json_file or not self.json_file.exists():
            return {}
        
        try:
            with open(self.json_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load context: {e}")
            return {}
    
    def _generate_summary(self, results: List[Dict]) -> Dict:
        """Generate validation summary from results"""
        total = len(results)
        successful = len([r for r in results if r['status'] == 'validated'])
        errors = len([r for r in results if r['status'] in ['error', 'api_error']])
        
        return {
            'total_rules': total,
            'successfully_validated': successful,
            'validation_errors': errors,
            'success_rate': (successful / total * 100) if total > 0 else 0
        }
    
    def save_results(self, results: Dict, output_file: str = None) -> str:
        """Save validation results to file"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"validation_results_{timestamp}.json"
        
        output_path = Path(output_file)
        
        # Create simplified output with just rule names and LLM responses
        simplified_results = {
            "validation_summary": results.get("validation_summary", {}),
            "rules": []
        }
        
        for rule_result in results.get("rule_results", []):
            if rule_result.get("status") == "validated":
                simplified_results["rules"].append({
                    "rule_name": rule_result.get("rule_name", ""),
                    "llm_response": rule_result.get("validation_content", "")
                })
            else:
                # Include error cases but simplified
                simplified_results["rules"].append({
                    "rule_name": rule_result.get("rule_name", ""),
                    "error": rule_result.get("error", "Unknown error")
                })
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(simplified_results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Validation results saved to: {output_path}")
        return str(output_path)
    
    def save_detailed_results(self, results: Dict, output_file: str = None) -> str:
        """Save detailed validation results including all API metadata"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"validation_results_detailed_{timestamp}.json"
        
        output_path = Path(output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Detailed validation results saved to: {output_path}")
        return str(output_path)
    
    def print_summary(self, results: Dict):
        """Print validation summary to console"""
        summary = results['validation_summary']
        
        print("\n" + "="*60)
        print("🎯 YARA VALIDATION SUMMARY")
        print("="*60)
        print(f"📊 Total Rules: {summary['total_rules']}")
        print(f"✅ Successfully Validated: {summary['successfully_validated']}")
        print(f"❌ Validation Errors: {summary['validation_errors']}")
        print(f"📈 Success Rate: {summary['success_rate']:.1f}%")
        print("="*60)
        
        if summary['validation_errors'] > 0:
            print("\n⚠️  Rules with validation errors:")
            for result in results['rule_results']:
                if result['status'] in ['error', 'api_error']:
                    print(f"   - {result['rule_name']}: {result.get('error', 'Unknown error')}")
        
        print(f"\n📁 Results saved to: {results.get('output_file', 'validation_results_*.json')}")
        print(f"📋 Log file: validation.log")
        print("\n💡 Output format: rule_name + LLM response (simplified)")

def main():
    parser = argparse.ArgumentParser(
        description="Validate YARA rules using Gocaas API LLM validation"
    )
    parser.add_argument(
        "yara_file", 
        help="Path to YARA rules file to validate"
    )
    parser.add_argument(
        "--json-file", "-j",
        help="Path to JSON signatures file for context (optional)"
    )
    parser.add_argument(
        "--max-rules", "-m",
        type=int,
        help="Maximum number of rules to validate"
    )
    parser.add_argument(
        "--sample", "-s",
        type=int,
        help="Randomly sample N rules for validation"
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
    parser.add_argument(
        "--detailed", "-d",
        action="store_true",
        help="Save detailed results including API metadata (default: simplified)"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize validator
        validator = YaraValidator(args.yara_file, args.json_file)
        
        # Run validation
        results = validator.validate_all_rules(
            max_rules=args.max_rules,
            sample_size=args.sample
        )
        
        # Save results
        if args.detailed:
            # Save full detailed results
            output_file = validator.save_detailed_results(results, args.output)
        else:
            # Save simplified results (default)
            output_file = validator.save_results(results, args.output)
        
        # Print summary
        validator.print_summary(results)
        
        # Exit with error code if validation failed
        if results['validation_summary']['validation_errors'] > 0:
            sys.exit(1)
        
    except Exception as e:
        logger.error(f"💥 Validation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()