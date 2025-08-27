#!/usr/bin/env python3
"""
YARA Syntax Validator
Validates YARA rules using the native yara command and provides syntax feedback
"""

import os
import sys
import json
import argparse
import logging
import subprocess
import re
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('yara_validation.log')
    ]
)
logger = logging.getLogger(__name__)

class YaraSyntaxValidator:
    """Validate YARA rules using native yara command"""
    
    def __init__(self):
        self.validation_results = []
        
    def validate_yara_file(self, yara_file: Path) -> Dict:
        """Validate a YARA file and return results"""
        logger.info(f"🔍 Validating YARA file: {yara_file}")
        
        if not yara_file.exists():
            return {
                'file': str(yara_file),
                'valid': False,
                'error': 'File not found',
                'rules': [],
                'timestamp': datetime.now().isoformat()
            }
        
        try:
            # Read the YARA file
            with open(yara_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Extract individual rules
            rules = self._extract_rules(content)
            
            validation_results = []
            overall_valid = True
            
            for rule in rules:
                rule_result = self._validate_single_rule(rule, yara_file)
                validation_results.append(rule_result)
                if not rule_result['valid']:
                    overall_valid = False
            
            return {
                'file': str(yara_file),
                'valid': overall_valid,
                'rules': validation_results,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"❌ Error validating {yara_file}: {e}")
            return {
                'file': str(yara_file),
                'valid': False,
                'error': str(e),
                'rules': [],
                'timestamp': datetime.now().isoformat()
            }
    
    def _extract_rules(self, content: str) -> List[Dict]:
        """Extract individual YARA rules from content"""
        rules = []
        
        # Split content into lines
        lines = content.split('\n')
        current_rule = []
        in_rule = False
        rule_name = ""
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            if line.startswith('rule '):
                # Start of new rule
                if in_rule and current_rule:
                    rules.append({
                        'name': rule_name,
                        'content': '\n'.join(current_rule),
                        'line_start': line_num - len(current_rule),
                        'line_end': line_num - 1
                    })
                
                # Start new rule
                rule_name = line.split()[1].split('{')[0]
                current_rule = [line]
                in_rule = True
                
            elif in_rule:
                current_rule.append(line)
                
                if line == '}':
                    # End of rule
                    rules.append({
                        'name': rule_name,
                        'content': '\n'.join(current_rule),
                        'line_start': line_num - len(current_rule) + 1,
                        'line_end': line_num
                    })
                    current_rule = []
                    in_rule = False
                    rule_name = ""
        
        # Add last rule if exists
        if in_rule and current_rule:
            rules.append({
                'name': rule_name,
                'content': '\n'.join(current_rule),
                'line_start': len(lines) - len(current_rule) + 1,
                'line_end': len(lines)
            })
        
        return rules
    
    def _validate_single_rule(self, rule: Dict, yara_file: Path) -> Dict:
        """Validate a single YARA rule"""
        rule_name = rule['name']
        rule_content = rule['content']
        
        logger.info(f"🔍 Validating rule: {rule_name}")
        
        # Create temporary file with just this rule
        temp_file = Path(f"temp_rule_{rule_name}.yar")
        
        try:
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(rule_content)
            
            # Validate using native yara command
            result = self._run_yara_validation(temp_file)
            
            # Clean up temp file
            temp_file.unlink()
            
            return {
                'name': rule_name,
                'valid': result['valid'],
                'errors': result['errors'],
                'warnings': result['warnings'],
                'line_start': rule['line_start'],
                'line_end': rule['line_end'],
                'content_preview': rule_content[:200] + '...' if len(rule_content) > 200 else rule_content
            }
            
        except Exception as e:
            logger.error(f"❌ Error validating rule {rule_name}: {e}")
            return {
                'name': rule_name,
                'valid': False,
                'errors': [f"Validation error: {e}"],
                'warnings': [],
                'line_start': rule['line_start'],
                'line_end': rule['line_end'],
                'content_preview': rule_content[:200] + '...' if len(rule_content) > 200 else rule_content
            }
    
    def _run_yara_validation(self, yara_file: Path) -> Dict:
        """Run native yara command to validate syntax"""
        try:
            # Use yara command to validate syntax
            # The -s flag shows string matches, -r shows rules, and we redirect output to /dev/null
            cmd = ['yara', '-s', '-r', str(yara_file), '/dev/null']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # No syntax errors
                return {
                    'valid': True,
                    'errors': [],
                    'warnings': []
                }
            else:
                # Parse error output
                errors = self._parse_yara_errors(result.stderr)
                return {
                    'valid': False,
                    'errors': errors,
                    'warnings': []
                }
                
        except subprocess.TimeoutExpired:
            return {
                'valid': False,
                'errors': ['Validation timeout'],
                'warnings': []
            }
        except FileNotFoundError:
            return {
                'valid': False,
                'errors': ['yara command not found. Please install YARA.'],
                'warnings': []
            }
        except Exception as e:
            return {
                'valid': False,
                'errors': [f'Validation failed: {e}'],
                'warnings': []
            }
    
    def _parse_yara_errors(self, stderr: str) -> List[str]:
        """Parse YARA error output"""
        errors = []
        
        if not stderr:
            return errors
        
        # Split by lines and look for error patterns
        for line in stderr.split('\n'):
            line = line.strip()
            if line and ('error:' in line or 'Error:' in line):
                errors.append(line)
        
        return errors if errors else [stderr.strip()]
    
    def save_validation_results(self, results: Dict, output_file: str = None) -> Path:
        """Save validation results to JSON file"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"yara_validation_{timestamp}.json"
        
        output_path = Path(output_file)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"💾 Validation results saved to: {output_path}")
        return output_path
    
    def print_validation_summary(self, results: Dict):
        """Print a summary of validation results"""
        print("\n" + "="*60)
        print("🔍 YARA SYNTAX VALIDATION SUMMARY")
        print("="*60)
        
        file_path = results['file']
        overall_valid = results['valid']
        rules = results['rules']
        
        print(f"📁 File: {file_path}")
        print(f"✅ Overall Status: {'VALID' if overall_valid else 'INVALID'}")
        print(f"📊 Rules Validated: {len(rules)}")
        print(f"⏰ Timestamp: {results['timestamp']}")
        
        if 'error' in results:
            print(f"❌ File Error: {results['error']}")
            return
        
        print(f"\n📋 Rule-by-Rule Results:")
        print("-" * 40)
        
        valid_count = 0
        invalid_count = 0
        
        for rule in rules:
            rule_name = rule['name']
            is_valid = rule['valid']
            status = "✅ VALID" if is_valid else "❌ INVALID"
            
            print(f"{status} | {rule_name}")
            
            if is_valid:
                valid_count += 1
            else:
                invalid_count += 1
                # Show errors
                for error in rule['errors']:
                    print(f"    ❌ Error: {error}")
        
        print(f"\n📊 Summary:")
        print(f"   ✅ Valid Rules: {valid_count}")
        print(f"   ❌ Invalid Rules: {invalid_count}")
        print(f"   📈 Success Rate: {(valid_count/len(rules)*100):.1f}%" if rules else "0%")

def main():
    parser = argparse.ArgumentParser(
        description="Validate YARA rules using native yara command"
    )
    parser.add_argument(
        "yara_file",
        help="Path to YARA file to validate"
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
        # Initialize validator
        validator = YaraSyntaxValidator()
        
        # Validate YARA file
        results = validator.validate_yara_file(Path(args.yara_file))
        
        # Save results
        output_file = validator.save_validation_results(results, args.output)
        
        # Print summary
        validator.print_validation_summary(results)
        
        # Exit with appropriate code
        if results['valid']:
            print("\n🎉 All YARA rules are syntactically valid!")
            sys.exit(0)
        else:
            print("\n⚠️  Some YARA rules have syntax errors. Check the details above.")
            sys.exit(1)
        
    except Exception as e:
        logger.error(f"💥 Validation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
