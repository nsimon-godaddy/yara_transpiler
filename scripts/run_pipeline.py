#!/usr/bin/env python3
"""
YARA Pipeline Automation Script
Runs the complete pipeline: txt_to_json -> transpile_to_yara -> [optional] llm_validation
"""

import os
import sys
import subprocess
import argparse
import logging
import json
import re
from pathlib import Path
from datetime import datetime
from typing import Dict, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('pipeline.log')
    ]
)
logger = logging.getLogger(__name__)

class PipelineRunner:
    def __init__(self, data_dir="data", scripts_dir="scripts", input_files=None):
        self.data_dir = Path(data_dir)
        self.scripts_dir = Path(scripts_dir)
        self.workspace_root = Path(__file__).parent.parent
        
        # Ensure we're in the right directory
        os.chdir(self.workspace_root)
        
        # Define file paths
        if input_files:
            self.input_files = [Path(f) for f in input_files]
        else:
            self.input_files = [self.data_dir / "signature_patterns.txt"]
        
        # Default output files (will be overridden for multiple inputs)
        self.json_file = self.data_dir / "signatures.json"
        self.yara_file = self.data_dir / "yara_rules.yar"
        
        # Script paths
        self.txt_to_json_script = self.scripts_dir / "txt_to_json.py"
        self.transpile_script = self.scripts_dir / "transpile_to_yara.py"
        self.validation_script = self.scripts_dir / "llm_validation.py"
    
    def check_prerequisites(self):
        """Check if all required files and dependencies exist"""
        logger.info("🔍 Checking prerequisites...")
        
        # Check if all input files exist
        for input_file in self.input_files:
            if not input_file.exists():
                raise FileNotFoundError(f"Input file not found: {input_file}")
        
        # Check if scripts exist
        if not self.txt_to_json_script.exists():
            raise FileNotFoundError(f"txt_to_json.py script not found: {self.txt_to_json_script}")
        
        if not self.transpile_script.exists():
            raise FileNotFoundError(f"transpile_to_yara.py script not found: {self.transpile_script}")
        
        # Check if data directory exists
        if not self.data_dir.exists():
            raise FileNotFoundError(f"Data directory not found: {self.data_dir}")
        
        logger.info(f"✅ All prerequisites met - {len(self.input_files)} input file(s) found")
    
    def run_txt_to_json(self):
        """Process all input files - convert text files to JSON, analyze binary files with LLM"""
        logger.info(f"🔄 Step 1: Processing {len(self.input_files)} input file(s)...")
        
        text_results = []
        binary_results = []
        
        for i, input_file in enumerate(self.input_files):
            logger.info(f"📁 Processing input file {i+1}/{len(self.input_files)}: {input_file.name}")
            
            # Check file type
            if input_file.suffix.lower() == '.txt':
                # Text file - convert to JSON
                result = self._process_text_file(input_file, i)
                text_results.append(result)
            else:
                # Binary file - analyze with LLM
                result = self._process_binary_file(input_file, i)
                binary_results.append(result)
        
        # Process text files through JSON conversion
        if text_results:
            successful_text = [r for r in text_results if r['success']]
            if successful_text:
                logger.info(f"🔄 Converting {len(successful_text)} text file(s) to JSON...")
                self.json_file = self._process_text_files_to_json(successful_text)
            else:
                logger.warning("⚠️  No text files were successfully converted")
        
        # Process binary files through LLM
        if binary_results:
            successful_binary = [r for r in binary_results if r['success']]
            if successful_binary:
                logger.info(f"🔄 Processing {len(successful_binary)} binary file(s) with LLM...")
                self.binary_yara_rules = self._extract_binary_yara_rules(successful_binary)
            else:
                logger.warning("⚠️  No binary files were successfully processed")
        
        # If no text files, create empty JSON structure
        if not text_results or not any(r['success'] for r in text_results):
            self.json_file = self._create_empty_json_structure()
        
        logger.info(f"✅ File processing completed: {len([r for r in text_results if r['success']])} text, {len([r for r in binary_results if r['success']])} binary")
        return {'text': text_results, 'binary': binary_results}
    
    def _combine_json_files(self, successful_conversions):
        """Combine multiple JSON files into a single merged JSON file"""
        import json
        
        combined_data = {
            'cleanup_constants': [],
            'signatures': []
        }
        
        # Track processed constants to avoid duplicates
        processed_constants = set()
        
        for conversion in successful_conversions:
            json_file = conversion['output']
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Add cleanup constants (avoiding duplicates)
                if 'cleanup_constants' in data:
                    for constant in data['cleanup_constants']:
                        constant_key = f"{constant.get('name', '')}:{constant.get('value', '')}"
                        if constant_key not in processed_constants:
                            combined_data['cleanup_constants'].append(constant)
                            processed_constants.add(constant_key)
                
                # Add signatures
                if 'signatures' in data:
                    combined_data['signatures'].extend(data['signatures'])
                
                logger.info(f"📋 Merged {json_file.name}: {len(data.get('signatures', []))} signatures, {len(data.get('cleanup_constants', []))} constants")
                
            except Exception as e:
                logger.warning(f"⚠️  Failed to merge {json_file.name}: {e}")
                continue
        
        # Create combined output file
        combined_file = self.data_dir / "signatures_combined.json"
        with open(combined_file, 'w', encoding='utf-8') as f:
            json.dump(combined_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📁 Combined JSON file created: {combined_file}")
        logger.info(f"📊 Total: {len(combined_data['signatures'])} signatures, {len(combined_data['cleanup_constants'])} constants")
        
        return combined_file
    
    def _process_text_file(self, input_file: Path, index: int) -> Dict:
        """Process a text file through JSON conversion"""
        # Generate output filename for this input
        if len(self.input_files) == 1:
            output_file = self.json_file
        else:
            # Create unique output filename for multiple inputs
            output_file = self.data_dir / f"signatures_{input_file.stem}.json"
        
        cmd = [
            sys.executable,
            str(self.txt_to_json_script),
            str(input_file),
            "--output", str(output_file)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                check=True
            )
            
            logger.info(f"✅ JSON conversion completed for {input_file.name}")
            if result.stdout:
                logger.info(f"Output: {result.stdout.strip()}")
            
            # Verify output file was created
            if not output_file.exists():
                raise FileNotFoundError(f"JSON file was not created for {input_file.name}")
            
            logger.info(f"📁 JSON file created: {output_file}")
            
            return {
                'input': input_file,
                'output': output_file,
                'success': True
            }
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ JSON conversion failed for {input_file.name} with exit code {e.returncode}")
            if e.stdout:
                logger.error(f"STDOUT: {e.stdout}")
            if e.stderr:
                logger.error(f"STDERR: {e.stderr}")
            return {
                'input': input_file,
                'output': output_file,
                'success': False,
                'error': f"Exit code {e.returncode}"
            }
        except Exception as e:
            logger.error(f"❌ Unexpected error during JSON conversion for {input_file.name}: {e}")
            return {
                'input': input_file,
                'output': output_file,
                'success': False,
                'error': str(e)
            }
    
    def _process_binary_file(self, input_file: Path, index: int) -> Dict:
        """Process a binary file through LLM analysis"""
        try:
            # Use the data classifier to analyze the binary file
            cmd = [
                sys.executable,
                str(self.scripts_dir / "data_classifier.py"),
                str(input_file)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                check=True
            )
            
            logger.info(f"✅ LLM analysis completed for {input_file.name}")
            if result.stdout:
                logger.info(f"Output: {result.stdout.strip()}")
            
            return {
                'input': input_file,
                'success': True,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ LLM analysis failed for {input_file.name} with exit code {e.returncode}")
            if e.stdout:
                logger.error(f"STDOUT: {e.stdout}")
            if e.stderr:
                logger.error(f"STDERR: {e.stderr}")
            return {
                'input': input_file,
                'success': False,
                'error': f"Exit code {e.returncode}"
            }
        except Exception as e:
            logger.error(f"❌ Unexpected error during LLM analysis for {input_file.name}: {e}")
            return {
                'input': input_file,
                'success': False,
                'error': str(e)
            }
    
    def _process_text_files_to_json(self, successful_text: List[Dict]) -> Path:
        """Process text files through JSON conversion and combining"""
        if len(successful_text) == 1:
            return successful_text[0]['output']
        else:
            # Multiple text files - combine them
            logger.info(f"🔄 Combining {len(successful_text)} JSON files into single output...")
            combined_file = self._combine_json_files(successful_text)
            # Clean up individual JSON files after combining
            self._cleanup_individual_json_files(successful_text)
            return combined_file
    
    def _extract_binary_yara_rules(self, successful_binary: List[Dict]) -> List[str]:
        """Extract YARA rules from binary file LLM analysis"""
        yara_rules = []
        
        for binary_result in successful_binary:
            input_file = binary_result['input']
            
            # Find the classification results file for this binary file
            classification_files = list(Path('.').glob(f"classification_results_*.json"))
            if not classification_files:
                logger.warning(f"⚠️  No classification results found for {input_file.name}")
                continue
            
            # Use the most recent classification file
            latest_classification = max(classification_files, key=lambda f: f.stat().st_mtime)
            
            try:
                with open(latest_classification, 'r', encoding='utf-8') as f:
                    classification_data = json.load(f)
                
                classification_content = classification_data.get('classification_content', '')
                
                # Look for YARA rule in the classification content
                import re
                # More flexible pattern to catch YARA rules with markdown formatting
                rule_pattern = r'```yara\s*\n(.*?)\n```'
                rule_matches = re.findall(rule_pattern, classification_content, re.DOTALL | re.IGNORECASE)
                
                # If no markdown pattern found, try the standard rule pattern
                if not rule_matches:
                    rule_pattern = r'rule\s+\w+\s*\{[^}]*\}'
                    rule_matches = re.findall(rule_pattern, classification_content, re.DOTALL | re.IGNORECASE)
                
                if rule_matches:
                    for rule in rule_matches:
                        # Clean up the rule syntax
                        cleaned_rule = self._clean_yara_rule_syntax(rule)
                        yara_rules.append(cleaned_rule)
                        logger.info(f"📋 Extracted YARA rule from {input_file.name}")
                else:
                    logger.warning(f"⚠️  No YARA rule found in classification results for {input_file.name}")
                    
            except Exception as e:
                logger.error(f"❌ Failed to read classification results for {input_file.name}: {e}")
                continue
        
        return yara_rules
    
    def _clean_yara_rule_syntax(self, rule: str) -> str:
        """Clean up YARA rule syntax to ensure proper formatting"""
        # Remove any markdown formatting
        rule = rule.replace('```yara', '').replace('```', '')
        
        # Ensure proper spacing
        rule = re.sub(r'\n\s*\n', '\n', rule)
        rule = rule.strip()
        
        return rule
    
    def _create_empty_json_structure(self) -> Path:
        """Create an empty JSON structure for when no text files are present"""
        empty_json = {
            'cleanup_constants': [],
            'signatures': []
        }
        
        output_file = self.data_dir / "signatures_empty.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(empty_json, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📁 Created empty JSON structure: {output_file}")
        return output_file
    
    def _append_binary_yara_rules(self):
        """Append binary file YARA rules to the existing YARA file"""
        try:
            # Read existing YARA file
            with open(self.yara_file, 'r', encoding='utf-8') as f:
                existing_content = f.read()
            
            # Add binary file rules
            binary_rules_content = "\n\n" + "\n\n".join(self.binary_yara_rules)
            
            # Write back with binary rules appended
            with open(self.yara_file, 'w', encoding='utf-8') as f:
                f.write(existing_content + binary_rules_content)
            
            logger.info(f"✅ Added {len(self.binary_yara_rules)} binary file YARA rules to {self.yara_file}")
            
        except Exception as e:
            logger.error(f"❌ Failed to append binary YARA rules: {e}")
    
    def _cleanup_individual_json_files(self, successful_conversions):
        """Clean up individual JSON files after combining them"""
        logger.info("🧹 Cleaning up individual JSON files...")
        
        for conversion in successful_conversions:
            json_file = conversion['output']
            try:
                if json_file.exists():
                    json_file.unlink()
                    logger.info(f"🗑️  Removed: {json_file.name}")
            except Exception as e:
                logger.warning(f"⚠️  Failed to remove {json_file.name}: {e}")
        
        logger.info("✅ Individual JSON files cleaned up")
    
    def run_transpile_to_yara(self):
        """Convert JSON to YARA rules and add binary file rules"""
        logger.info("🔄 Step 2: Converting JSON to YARA rules...")
        
        # First, convert JSON to YARA rules
        cmd = [
            sys.executable,
            str(self.transpile_script),
            str(self.json_file),
            str(self.yara_file)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                check=True
            )
            
            logger.info("✅ JSON to YARA conversion completed successfully")
            if result.stdout:
                logger.info(f"Output: {result.stdout.strip()}")
            
            # Verify output file was created
            if not self.yara_file.exists():
                raise FileNotFoundError("YARA file was not created")
            
            logger.info(f"📁 YARA file created: {self.yara_file}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ YARA conversion failed with exit code {e.returncode}")
            if e.stdout:
                logger.error(f"STDOUT: {e.stdout}")
            if e.stderr:
                logger.error(f"STDERR: {e.stderr}")
            raise
        except Exception as e:
            logger.error(f"❌ Unexpected error during YARA conversion: {e}")
            raise
        
        # Now add binary file YARA rules if any exist
        if hasattr(self, 'binary_yara_rules') and self.binary_yara_rules:
            logger.info(f"🔄 Adding {len(self.binary_yara_rules)} binary file YARA rules...")
            self._append_binary_yara_rules()
    
    def run_llm_validation(self, max_rules=None, sample_size=None):
        """Run the LLM validation step using Gocaas API"""
        logger.info("🔄 Step 3: Running LLM validation of YARA rules...")
        
        if not self.validation_script.exists():
            logger.warning("⚠️  LLM validation script not found, skipping validation step")
            return
        
        # Check if required environment variables are set
        if not os.getenv("JWT") or not os.getenv("API_URL"):
            logger.warning("⚠️  JWT or API_URL environment variables not set, skipping validation")
            logger.info("💡 Set JWT and API_URL in .env file to enable LLM validation")
            return
        
        cmd = [
            sys.executable,
            str(self.validation_script),
            str(self.yara_file),
            "--json-file", str(self.json_file)
        ]
        
        # Add optional parameters
        if max_rules:
            cmd.extend(["--max-rules", str(max_rules)])
        if sample_size:
            cmd.extend(["--sample", str(sample_size)])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                check=True
            )
            
            logger.info("✅ LLM validation completed successfully")
            if result.stdout:
                logger.info(f"Output: {result.stdout.strip()}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ LLM validation failed with exit code {e.returncode}")
            if e.stdout:
                logger.error(f"STDOUT: {e.stdout}")
            if e.stderr:
                logger.error(f"STDERR: {e.stderr}")
            # Don't fail the pipeline for validation errors
            logger.warning("⚠️  Continuing pipeline despite validation errors")
        except Exception as e:
            logger.error(f"❌ Unexpected error during LLM validation: {e}")
            logger.warning("⚠️  Continuing pipeline despite validation errors")
    
    def validate_outputs(self):
        """Validate the generated output files"""
        logger.info("🔍 Validating output files...")
        
        # Check JSON file
        if self.json_file.exists():
            try:
                import json
                with open(self.json_file, 'r') as f:
                    data = json.load(f)
                
                signature_count = len(data.get('signatures', []))
                constants_count = len(data.get('cleanup_constants', []))
                
                logger.info(f"📊 JSON validation: {signature_count} signatures, {constants_count} constants")
                
            except json.JSONDecodeError as e:
                logger.error(f"❌ Invalid JSON in output file: {e}")
                raise
            except Exception as e:
                logger.error(f"❌ Error validating JSON file: {e}")
                raise
        
        # Check YARA file
        if self.yara_file.exists():
            try:
                with open(self.yara_file, 'r') as f:
                    content = f.read()
                
                # Count YARA rules (look for "rule" keyword)
                rule_count = content.count('rule ')
                logger.info(f"📊 YARA validation: {rule_count} rules generated")
                
                if rule_count == 0:
                    logger.warning("⚠️  No YARA rules found in output file")
                
            except Exception as e:
                logger.error(f"❌ Error validating YARA file: {e}")
                raise
        
        logger.info("✅ Output validation completed")
    
    def run_pipeline(self, clean=False, validate=False, max_rules=None, sample_size=None):
        """Run the complete pipeline"""
        start_time = datetime.now()
        logger.info("🚀 Starting YARA pipeline...")
        logger.info(f"📁 Working directory: {self.workspace_root}")
        
        try:
            # Clean previous outputs if requested
            if clean:
                self.clean_outputs()
            
            # Check prerequisites
            self.check_prerequisites()
            
            # Run the pipeline steps
            self.run_txt_to_json()
            self.run_transpile_to_yara()
            
            # Run LLM validation if requested
            if validate:
                self.run_llm_validation(max_rules, sample_size)
            
            # Validate outputs
            self.validate_outputs()
            
            end_time = datetime.now()
            duration = end_time - start_time
            
            logger.info("🎉 Pipeline completed successfully!")
            logger.info(f"⏱️  Total duration: {duration}")
            logger.info(f"📁 Final outputs:")
            logger.info(f"   - JSON: {self.json_file}")
            logger.info(f"   - YARA: {self.yara_file}")
            
            if validate:
                logger.info("🔍 LLM validation results saved to validation_results_*.json")
            
        except Exception as e:
            logger.error(f"💥 Pipeline failed: {e}")
            raise
    
    def clean_outputs(self):
        """Clean previous output files"""
        logger.info("🧹 Cleaning previous output files...")
        
        files_to_clean = [self.json_file, self.yara_file]
        
        for file_path in files_to_clean:
            if file_path.exists():
                try:
                    file_path.unlink()
                    logger.info(f"🗑️  Deleted: {file_path}")
                except Exception as e:
                    logger.warning(f"⚠️  Could not delete {file_path}: {e}")
    
    def show_status(self):
        """Show the current status of pipeline files"""
        logger.info("📊 Pipeline Status:")
        
        # Show input files
        logger.info(f"   Input files ({len(self.input_files)}):")
        for i, input_file in enumerate(self.input_files):
            status = '✅' if input_file.exists() else '❌'
            logger.info(f"     {i+1}. {input_file} {status}")
        
        logger.info(f"   JSON file: {self.json_file} {'✅' if self.json_file.exists() else '❌'}")
        logger.info(f"   YARA file: {self.yara_file} {'✅' if self.yara_file.exists() else '❌'}")
        
        # Check validation script
        if self.validation_script.exists():
            logger.info(f"   Validation script: {self.validation_script} ✅")
        else:
            logger.info(f"   Validation script: {self.validation_script} ❌")
        
        # Check environment variables
        if os.getenv("JWT") and os.getenv("API_URL"):
            logger.info("   Environment variables: JWT ✅ API_URL ✅")
        else:
            logger.info("   Environment variables: JWT ❌ API_URL ❌")

def main():
    parser = argparse.ArgumentParser(
        description='Run the complete YARA pipeline: txt_to_json -> transpile_to_yara -> [optional] llm_validation'
    )
    parser.add_argument(
        "input_files",
        nargs="*",
        help="Input text files to process (default: data/signature_patterns.txt)"
    )
    parser.add_argument(
        "--clean", 
        action="store_true", 
        help="Clean previous output files before running"
    )
    parser.add_argument(
        "--status", 
        action="store_true", 
        help="Show current pipeline status and exit"
    )
    parser.add_argument(
        "--validate", 
        action="store_true", 
        help="Run LLM validation after YARA generation"
    )
    parser.add_argument(
        "--max-rules", 
        type=int, 
        help="Maximum number of rules to validate (requires --validate)"
    )
    parser.add_argument(
        "--sample", 
        type=int, 
        help="Randomly sample N rules for validation (requires --validate)"
    )
    parser.add_argument(
        "--data-dir", 
        default="data", 
        help="Data directory path (default: data)"
    )
    parser.add_argument(
        "--scripts-dir", 
        default="scripts", 
        help="Scripts directory path (default: scripts)"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if (args.max_rules or args.sample) and not args.validate:
        logger.error("❌ --max-rules and --sample require --validate flag")
        sys.exit(1)
    
    try:
        # Use provided input files or default
        input_files = args.input_files if args.input_files else None
        
        runner = PipelineRunner(args.data_dir, args.scripts_dir, input_files)
        
        if args.status:
            runner.show_status()
            return
        
        runner.run_pipeline(
            clean=args.clean,
            validate=args.validate,
            max_rules=args.max_rules,
            sample_size=args.sample
        )
        
    except KeyboardInterrupt:
        logger.info("⏹️  Pipeline interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"💥 Pipeline failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
