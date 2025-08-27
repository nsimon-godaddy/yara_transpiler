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
from typing import Dict, List, Optional

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
                logger.warning("⚠️  No text files were successfully processed")
                self.json_file = self._create_empty_json_structure()
        else:
            logger.info("📁 No text files to process")
            self.json_file = self._create_empty_json_structure()
        
        # Store binary results for later YARA generation
        self.binary_yara_rules = []
        if binary_results:
            successful_binary = [r for r in binary_results if r['success']]
            if successful_binary:
                logger.info(f"🔄 Processing {len(successful_binary)} binary file(s) with LLM...")
                self.binary_yara_rules = self._process_binary_files_with_llm(successful_binary)
                logger.info(f"✅ Extracted {len(self.binary_yara_rules)} YARA rules from binary files")
            else:
                logger.warning("⚠️  No binary files were successfully processed")
        
        logger.info("✅ Step 1 completed")
    
    def _process_text_file(self, input_file: Path, index: int) -> Dict:
        """Process a single text file through txt_to_json.py"""
        try:
            # Create unique output filename for this input
            output_file = self.data_dir / f"signatures_{input_file.stem}_{index}.json"
            
            # Run txt_to_json.py
            cmd = [
                sys.executable,
                str(self.txt_to_json_script),
                str(input_file),
                "--output", str(output_file)
            ]
            
            logger.debug(f"🔧 Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                check=True,
                timeout=60
            )
            
            if result.returncode == 0:
                logger.info(f"✅ Successfully converted {input_file.name} to JSON")
                return {
                    'success': True,
                    'input_file': input_file,
                    'output_file': output_file,
                    'index': index
                }
            else:
                logger.error(f"❌ txt_to_json.py failed for {input_file.name}")
                return {
                    'success': False,
                    'input_file': input_file,
                    'error': f"Exit code: {result.returncode}"
                }
                
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ txt_to_json.py failed for {input_file.name}: {e}")
            return {
                'success': False,
                'input_file': input_file,
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"❌ Unexpected error processing {input_file.name}: {e}")
            return {
                'success': False,
                'input_file': input_file,
                'error': str(e)
            }
    
    def _process_binary_file(self, input_file: Path, index: int) -> Dict:
        """Process a single binary file through data_classifier.py with prompt optimization"""
        try:
            logger.info(f"🔍 Analyzing binary file: {input_file.name}")
            
            # First, run prompt optimizer to analyze the file
            prompt_optimizer_cmd = [
                sys.executable,
                str(self.scripts_dir / "prompt_optimizer.py"),
                str(input_file)
            ]
            
            logger.debug(f"🔧 Running prompt optimizer: {' '.join(prompt_optimizer_cmd)}")
            
            prompt_result = subprocess.run(
                prompt_optimizer_cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                check=True,
                timeout=60
            )
            
            if prompt_result.returncode == 0:
                logger.info(f"✅ Prompt optimization completed for {input_file.name}")
                
                # Find the optimization results file
                optimization_files = list(Path('.').glob(f"prompt_optimization_{input_file.stem}_*.json"))
                if optimization_files:
                    # Use the most recent optimization file
                    latest_optimization = max(optimization_files, key=lambda f: f.stat().st_mtime)
                    
                    try:
                        with open(latest_optimization, 'r', encoding='utf-8') as f:
                            prompt_data = json.load(f)
                        optimized_prompt = prompt_data.get('optimized_prompt', '')
                        
                        if optimized_prompt:
                            logger.info(f"📝 Using optimized prompt for {input_file.name}")
                            logger.debug(f"📋 Prompt preview: {optimized_prompt[:200]}...")
                        else:
                            logger.warning(f"⚠️  No optimized prompt found for {input_file.name}")
                            optimized_prompt = ""
                            
                    except Exception as e:
                        logger.warning(f"⚠️  Could not read optimization file for {input_file.name}: {e}")
                        optimized_prompt = ""
                else:
                    logger.warning(f"⚠️  No optimization results file found for {input_file.name}")
                    optimized_prompt = ""
            else:
                logger.warning(f"⚠️  Prompt optimization failed for {input_file.name}, using default")
                optimized_prompt = ""
            
            # Now run data classifier with the optimized prompt
            classifier_cmd = [
                sys.executable,
                str(self.scripts_dir / "data_classifier.py"),
                str(input_file)
            ]
            
            if optimized_prompt:
                classifier_cmd.extend(["--custom-prompt", optimized_prompt])
            
            logger.debug(f"🔧 Running data classifier: {' '.join(classifier_cmd)}")
            
            result = subprocess.run(
                classifier_cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                check=True,
                timeout=120
            )
            
            if result.returncode == 0:
                logger.info(f"✅ Data classification completed for {input_file.name}")
                
                # Save classification results
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                classification_file = self.data_dir / f"classification_{input_file.stem}_{timestamp}.json"
                
                # The data classifier saves results to a file, so we need to read that file
                # Find the classification results file
                classification_files = list(Path('.').glob(f"classification_{input_file.stem}_*.json"))
                if classification_files:
                    # Use the most recent classification file
                    latest_classification = max(classification_files, key=lambda f: f.stat().st_mtime)
                    
                    try:
                        with open(latest_classification, 'r', encoding='utf-8') as f:
                            classification_data = json.load(f)
                        
                        # Update the classification file path to the actual file found
                        classification_file = latest_classification
                        
                        logger.info(f"💾 Classification results loaded from {classification_file}")
                        
                        return {
                            'success': True,
                            'input_file': input_file,
                            'classification_file': classification_file,
                            'classification_data': classification_data,
                            'index': index
                        }
                    except Exception as e:
                        logger.error(f"❌ Failed to read classification file for {input_file.name}: {e}")
                        return {
                            'success': False,
                            'input_file': input_file,
                            'error': f"File read error: {e}"
                        }
                else:
                    logger.warning(f"⚠️  No classification results file found for {input_file.name}")
                    return {
                        'success': False,
                        'input_file': input_file,
                        'error': "No classification file found"
                    }
            else:
                logger.error(f"❌ Data classification failed for {input_file.name}")
                return {
                    'success': False,
                    'input_file': input_file,
                    'error': f"Exit code: {result.returncode}"
                }
                
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Binary file processing failed for {input_file.name}: {e}")
            return {
                'success': False,
                'input_file': input_file,
                'error': str(e)
            }
        except Exception as e:
            logger.error(f"❌ Unexpected error processing binary file {input_file.name}: {e}")
            return {
                'success': False,
                'input_file': input_file,
                'error': str(e)
            }
    
    def _process_text_files_to_json(self, text_results: List[Dict]) -> Path:
        """Combine multiple text file JSON outputs into a single file"""
        try:
            if len(text_results) == 1:
                # Single file, just rename it
                single_result = text_results[0]
                final_json = self.data_dir / "signatures.json"
                single_result['output_file'].rename(final_json)
                logger.info(f"📁 Single JSON file created: {final_json}")
                return final_json
            
            # Multiple files, combine them
            logger.info(f"🔄 Combining {len(text_results)} JSON files...")
            
            combined_signatures = []
            combined_cleanup_constants = []
            
            for result in text_results:
                try:
                    with open(result['output_file'], 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # Collect signatures
                    if 'signatures' in data:
                        combined_signatures.extend(data['signatures'])
                    
                    # Collect cleanup constants
                    if 'cleanup_constants' in data:
                        combined_cleanup_constants.extend(data['cleanup_constants'])
                        
                except Exception as e:
                    logger.warning(f"⚠️  Could not read {result['output_file']}: {e}")
                    continue
            
            # Create combined JSON
            combined_data = {
                'cleanup_constants': combined_cleanup_constants,
                'signatures': combined_signatures
            }
            
            final_json = self.data_dir / "signatures_combined.json"
            with open(final_json, 'w', encoding='utf-8') as f:
                json.dump(combined_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"📁 Combined JSON created: {final_json} ({len(combined_signatures)} signatures)")
            
            # Clean up individual files
            self._cleanup_individual_json_files(text_results)
            
            return final_json
            
        except Exception as e:
            logger.error(f"❌ Failed to combine JSON files: {e}")
            # Fallback to first successful result
            if text_results:
                return text_results[0]['output_file']
            else:
                raise
    
    def _cleanup_individual_json_files(self, text_results: List[Dict]):
        """Remove individual JSON files after combining"""
        for result in text_results:
            if 'output_file' in result and result['output_file'].exists():
                try:
                    result['output_file'].unlink()
                    logger.debug(f"🗑️  Removed individual JSON: {result['output_file']}")
                except Exception as e:
                    logger.warning(f"⚠️  Could not remove {result['output_file']}: {e}")
    
    def _process_binary_files_with_llm(self, binary_files: List[Dict]) -> List[str]:
        """Process binary files with LLM to extract YARA rules"""
        logger.info(f"🔄 Processing {len(binary_files)} binary file(s) with LLM...")
        
        yara_rules = []
        processed_rules = set()
        
        for binary_file in binary_files:
            input_file = Path(binary_file['input_file'])
            classification_file = binary_file['classification_file']
            
            try:
                # Read classification results
                with open(classification_file, 'r', encoding='utf-8') as f:
                    classification_data = json.load(f)
                
                # Extract YARA rule from classification content
                classification_content = classification_data.get('classification_content', '')
                
                if not classification_content:
                    logger.warning(f"⚠️  No classification content found for {input_file.name}")
                    continue
                
                # Look for YARA rule in the content
                # Try markdown format first (most common)
                rule_pattern = r'```yara\s*\n(.*?)\n```'
                rule_matches = re.findall(rule_pattern, classification_content, re.DOTALL | re.IGNORECASE)
                
                if not rule_matches:
                    # Try standard rule format without markdown
                    # Use brace counting to find complete rules
                    rule_start_pattern = r'rule\s+\w+\s*\{'
                    rule_starts = list(re.finditer(rule_start_pattern, classification_content, re.IGNORECASE))
                    
                    if rule_starts:
                        for match in rule_starts:
                            start_pos = match.start()
                            # Count braces to find the end
                            brace_count = 0
                            for i, char in enumerate(classification_content[start_pos:], start_pos):
                                if char == '{':
                                    brace_count += 1
                                elif char == '}':
                                    brace_count -= 1
                                    if brace_count == 0:
                                        # Found complete rule
                                        complete_rule = classification_content[start_pos:i+1]
                                        rule_matches.append(complete_rule)
                                        break
                    else:
                        # Fallback to old pattern
                        rule_pattern = r'rule\s+\w+\s*\{[^}]*\}'
                        rule_matches = re.findall(rule_pattern, classification_content, re.DOTALL | re.IGNORECASE)
                
                if rule_matches:
                    for rule in rule_matches:
                        # Clean up the rule syntax and rename based on input file
                        cleaned_rule = self._clean_yara_rule_syntax(rule, input_file.stem)
                        
                        # Create a unique identifier for this rule to prevent duplicates
                        rule_id = self._create_rule_identifier(cleaned_rule)
                        
                        if rule_id not in processed_rules:
                            processed_rules.add(rule_id)
                            
                            # Validate rule through syntax layer before adding
                            validated_rule = self._validate_rule_through_syntax_layer(cleaned_rule, input_file.stem)
                            yara_rules.append(validated_rule)
                            
                            logger.info(f"📋 Extracted YARA rule from {input_file.name}")
                        else:
                            logger.info(f"🔄 Skipping duplicate rule from {input_file.name}")
                else:
                    logger.warning(f"⚠️  No YARA rule found in classification results for {input_file.name}")
                    
            except Exception as e:
                logger.error(f"❌ Failed to read classification results for {input_file.name}: {e}")
                continue
        
        return yara_rules
    
    def _validate_rule_through_syntax_layer(self, rule_content: str, rule_name: str) -> str:
        """Validate YARA rule through the syntax layer before adding to file"""
        try:
            # Check if syntax layer exists
            syntax_layer_script = self.scripts_dir / "yara_syntax_layer.py"
            if not syntax_layer_script.exists():
                logger.warning("⚠️  YARA syntax layer not found, using original rule")
                return rule_content
            
            # Create temporary file with single rule for validation
            temp_rules_file = self.workspace_root / f"temp_rules_{rule_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            # Format rules for syntax layer
            rules_data = [{
                'name': rule_name,
                'content': rule_content,
                'source': 'llm_generation'
            }]
            
            with open(temp_rules_file, 'w', encoding='utf-8') as f:
                json.dump(rules_data, f, indent=2, ensure_ascii=False)
            
            try:
                # Run syntax layer validation
                syntax_cmd = [
                    sys.executable,
                    str(syntax_layer_script),
                    str(temp_rules_file),
                    "--output", str(temp_rules_file.parent / f"syntax_validation_{rule_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                ]
                
                logger.debug(f"🔍 Running YARA syntax layer validation for rule: {rule_name}")
                
                result = subprocess.run(
                    syntax_cmd,
                    capture_output=True,
                    text=True,
                    cwd=self.workspace_root,
                    timeout=60
                )
                
                if result.returncode == 0:
                    logger.info(f"✅ Rule {rule_name} validated through syntax layer")
                    
                    # Try to read the corrected rule from validation results
                    try:
                        # Look for validation results in the output
                        for line in result.stdout.split('\n'):
                            if 'syntax_validation_' in line and '.json' in line:
                                validation_file = line.split()[-1]
                                with open(validation_file, 'r') as f:
                                    validation_data = json.load(f)
                                
                                if validation_data and len(validation_data) > 0:
                                    corrected_rule = validation_data[0].get('content', rule_content)
                                    if corrected_rule != rule_content:
                                        logger.info(f"🔧 Rule {rule_name} syntax corrected by syntax layer")
                                        return corrected_rule
                                    else:
                                        logger.info(f"✅ Rule {rule_name} syntax already valid")
                                        return rule_content
                    except Exception as e:
                        logger.warning(f"⚠️  Could not read syntax validation results: {e}")
                        return rule_content
                else:
                    logger.warning(f"⚠️  Syntax layer validation failed for rule {rule_name}: {result.stderr}")
                    return rule_content
                    
            finally:
                # Clean up temporary files
                if temp_rules_file.exists():
                    temp_rules_file.unlink()
                
                # Clean up validation result files
                for file in self.workspace_root.glob(f"syntax_validation_{rule_name}_*.json"):
                    try:
                        file.unlink()
                    except:
                        pass
                        
        except Exception as e:
            logger.warning(f"⚠️  Syntax layer validation failed for rule {rule_name}: {e}")
            return rule_content
    
    def _clean_yara_rule_syntax(self, rule: str, input_stem: str) -> str:
        """Clean up YARA rule syntax to ensure proper formatting"""
        import re
        
        # Remove any markdown formatting
        rule = rule.replace('```yara', '').replace('```', '')
        
        # Ensure proper spacing
        rule = re.sub(r'\n\s*\n', '\n', rule)
        rule = rule.strip()
        
        # Rename rule to match input file stem
        rule_name_match = re.search(r'rule\s+(\w+)', rule)
        if rule_name_match:
            old_rule_name = rule_name_match.group(1)
            
            # Ensure the new rule name doesn't start with a number
            # YARA rule names must start with a letter or underscore
            # Replace dashes and spaces with underscores
            clean_stem = input_stem.replace('-', '_').replace(' ', '_') if input_stem else ""
            
            if clean_stem and clean_stem[0].isdigit():
                new_rule_name = f"file_{clean_stem}"
            else:
                new_rule_name = clean_stem
            
            # Replace the old rule name with the new rule name
            rule = re.sub(rf'rule\s+{re.escape(old_rule_name)}\s*{{', f'rule {new_rule_name} {{', rule)
        
        return rule
    
    def _create_rule_identifier(self, rule: str) -> str:
        """Create a unique identifier for a YARA rule to help with deduplication"""
        import re
        
        # Extract rule name
        rule_name_match = re.search(r'rule\s+(\w+)', rule)
        rule_name = rule_name_match.group(1) if rule_name_match else "unknown"
        
        # Extract key strings (first few)
        strings_matches = re.findall(r'\$\w+\s*=\s*"([^"]+)"', rule)
        key_strings = strings_matches[:3]  # Use first 3 strings
        
        # Create identifier from rule name and key strings
        identifier = f"{rule_name}:{':'.join(key_strings)}"
        return identifier.lower()
    
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
            
            # Write back to file
            with open(self.yara_file, 'w', encoding='utf-8') as f:
                f.write(existing_content + binary_rules_content)
            
            logger.info(f"✅ Appended {len(self.binary_yara_rules)} binary file rules to {self.yara_file}")
            
        except Exception as e:
            logger.error(f"❌ Failed to append binary file rules: {e}")
    
    def run_transpile_to_yara(self):
        """Convert JSON signatures to YARA rules"""
        logger.info("🔄 Step 2: Converting JSON to YARA rules...")
        
        try:
            # Run transpile_to_yara.py
            cmd = [
                sys.executable,
                str(self.transpile_script),
                str(self.json_file),
                str(self.yara_file)
            ]
            
            logger.debug(f"🔧 Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                check=True,
                timeout=60
            )
            
            if result.returncode == 0:
                logger.info(f"✅ Successfully converted JSON to YARA rules: {self.yara_file}")
                
                # Append binary file rules if any
                if hasattr(self, 'binary_yara_rules') and self.binary_yara_rules:
                    self._append_binary_yara_rules()
                
                logger.info("✅ Step 2 completed")
            else:
                logger.error(f"❌ transpile_to_yara.py failed with exit code {result.returncode}")
                raise subprocess.CalledProcessError(result.returncode, cmd)
                
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ transpile_to_yara.py failed: {e}")
            raise
        except Exception as e:
            logger.error(f"❌ Unexpected error in transpile_to_yara: {e}")
            raise
    
    def run_llm_validation(self, output_file: str = None):
        """Run LLM validation on the generated YARA rules"""
        logger.info("🔄 Step 3: Running LLM validation...")
        
        try:
            # Check if validation script exists
            if not self.validation_script.exists():
                logger.warning("⚠️  LLM validation script not found, skipping validation")
                return
            
            # Build validation command
            cmd = [
                sys.executable,
                str(self.validation_script),
                str(self.yara_file),
                "--json-file", str(self.json_file)
            ]
            
            if output_file:
                cmd.extend(["--output", output_file])
            
            logger.debug(f"🔧 Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                check=True,
                timeout=300  # 5 minutes for validation
            )
            
            if result.returncode == 0:
                logger.info("✅ LLM validation completed successfully")
                logger.info("✅ Step 3 completed")
            else:
                logger.error(f"❌ LLM validation failed with exit code {result.returncode}")
                
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ LLM validation failed: {e}")
        except Exception as e:
            logger.error(f"❌ Unexpected error in LLM validation: {e}")
    
    def get_latest_validation_results(self) -> Dict:
        """Get the latest YARA validation results for later use"""
        validation_dir = self.workspace_root / "validation_results"
        
        if not validation_dir.exists():
            return {}
        
        # Find the most recent validation file
        validation_files = list(validation_dir.glob("yara_validation_*.json"))
        if not validation_files:
            return {}
        
        # Sort by modification time and get the latest
        latest_file = max(validation_files, key=lambda f: f.stat().st_mtime)
        
        try:
            with open(latest_file, 'r', encoding='utf-8') as f:
                results = json.load(f)
            
            # Add the file path to the results for reference
            results['validation_file'] = str(latest_file)
            return results
            
        except Exception as e:
            logger.warning(f"⚠️  Could not load validation results from {latest_file}: {e}")
            return {}
    
    def run_yara_syntax_validation(self):
        """Run YARA syntax validation on generated rules"""
        try:
            logger.info("🔍 Running YARA syntax validation...")
            
            if not self.yara_file.exists():
                logger.warning("⚠️  No YARA file to validate")
                return
            
            # Create validation results directory
            validation_dir = self.workspace_root / "validation_results"
            validation_dir.mkdir(exist_ok=True)
            
            # Run YARA syntax validator with output to validation directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = validation_dir / f"yara_validation_{timestamp}.json"
            
            validator_cmd = [
                sys.executable,
                str(self.scripts_dir / "yara_syntax_validator.py"),
                str(self.yara_file),
                "--output", str(output_file)
            ]
            
            logger.debug(f"🔧 Running YARA syntax validator: {' '.join(validator_cmd)}")
            
            result = subprocess.run(
                validator_cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                timeout=60
            )
            
            if result.returncode == 0:
                logger.info("✅ YARA syntax validation completed successfully")
                logger.info("✅ All generated rules are syntactically valid")
                logger.info(f"💾 Validation results stored in: {output_file}")
            else:
                logger.warning(f"⚠️  YARA syntax validation found issues: {result.stderr}")
                logger.info(f"📋 Validation feedback stored in: {output_file}")
                logger.info("📋 Check the validation results for syntax errors and feedback")
                
                # Automatically attempt to revise invalid rules
                self.attempt_rule_revision(output_file)
                
        except subprocess.TimeoutExpired:
            logger.warning("⚠️  YARA syntax validation timed out")
        except subprocess.CalledProcessError as e:
            logger.warning(f"⚠️  YARA syntax validation failed: {e}")
        except Exception as e:
            logger.warning(f"⚠️  Unexpected error in YARA syntax validation: {e}")
    
    def attempt_rule_revision(self, validation_file: Path):
        """Attempt to automatically revise invalid YARA rules using specialized YARA revision service"""
        try:
            logger.info("🔧 Attempting automatic YARA rule revision using specialized service...")
            
            # Check if specialized revision service exists
            revision_service = self.scripts_dir / "yara_revision_service.py"
            if not revision_service.exists():
                logger.warning("⚠️  Specialized YARA revision service not found, skipping automatic revision")
                return
            
            # Get current environment variables
            current_env = os.environ.copy()
            
            # Ensure JWT and API_URL are available to subprocess
            if 'JWT' not in current_env:
                logger.warning("⚠️  JWT not found in environment, attempting to load from .env")
                from dotenv import load_dotenv
                load_dotenv()
                current_env['JWT'] = os.getenv('JWT', '')
                current_env['API_URL'] = os.getenv('API_URL', '')
            
            # Run specialized YARA rule revision
            revision_cmd = [
                sys.executable,
                str(revision_service),
                str(validation_file),
                str(self.yara_file),
                "--output", str(validation_file.parent / f"yara_revision_service_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            ]
            
            logger.debug(f"🔧 Running specialized YARA revision service: {' '.join(revision_cmd)}")
            logger.debug(f"🔧 Environment check - JWT: {'SET' if current_env.get('JWT') else 'NOT SET'}, API_URL: {'SET' if current_env.get('API_URL') else 'NOT SET'}")
            
            result = subprocess.run(
                revision_cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                timeout=120,
                env=current_env  # Explicitly pass environment variables
            )
            
            if result.returncode == 0:
                logger.info("✅ Specialized YARA rule revision completed successfully")
                logger.info("📋 Check revision service results for updated rules")
                
                # Re-validate the revised rules
                self.revalidate_after_revision()
            else:
                logger.warning(f"⚠️  Specialized YARA rule revision failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.warning("⚠️  Specialized YARA rule revision timed out")
        except subprocess.CalledProcessError as e:
            logger.warning(f"⚠️  Specialized YARA rule revision failed: {e}")
        except Exception as e:
            logger.warning(f"⚠️  Unexpected error in specialized YARA rule revision: {e}")
    
    def revalidate_after_revision(self):
        """Re-validate YARA rules after revision to check if issues were resolved"""
        try:
            logger.info("🔍 Re-validating YARA rules after revision...")
            
            # Run YARA syntax validation again
            validation_dir = self.workspace_root / "validation_results"
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = validation_dir / f"yara_validation_post_revision_{timestamp}.json"
            
            validator_cmd = [
                sys.executable,
                str(self.scripts_dir / "yara_syntax_validator.py"),
                str(self.yara_file),
                "--output", str(output_file)
            ]
            
            result = subprocess.run(
                validator_cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                timeout=60
            )
            
            if result.returncode == 0:
                logger.info("✅ Post-revision validation successful - all rules are now valid!")
                logger.info(f"💾 Post-revision validation results stored in: {output_file}")
            else:
                logger.warning(f"⚠️  Post-revision validation still found issues: {result.stderr}")
                logger.info(f"📋 Post-revision validation results stored in: {output_file}")
                
        except Exception as e:
            logger.warning(f"⚠️  Post-revision validation failed: {e}")
    
    def validate_outputs(self):
        """Validate that the pipeline produced the expected outputs"""
        logger.info("🔍 Validating pipeline outputs...")
        
        # Check JSON file
        if self.json_file.exists():
            try:
                with open(self.json_file, 'r') as f:
                    json_data = json.load(f)
                signature_count = len(json_data.get('signatures', []))
                logger.info(f"✅ JSON file created: {self.json_file} ({signature_count} signatures)")
            except Exception as e:
                logger.error(f"❌ JSON file validation failed: {e}")
        else:
            logger.error(f"❌ JSON file not found: {self.json_file}")
        
        # Check YARA file
        if self.yara_file.exists():
            try:
                with open(self.yara_file, 'r') as f:
                    yara_content = f.read()
                
                # Count YARA rules
                rule_count = len(re.findall(r'^rule\s+\w+', yara_content, re.MULTILINE))
                logger.info(f"✅ YARA file created: {self.yara_file} ({rule_count} rules)")
            except Exception as e:
                logger.error(f"❌ YARA file validation failed: {e}")
        else:
            logger.error(f"❌ YARA file not found: {self.yara_file}")
    
    def run_pipeline(self, skip_validation: bool = False, output_file: str = None):
        """Run the complete pipeline"""
        try:
            logger.info("🚀 Starting YARA Pipeline...")
            
            # Check prerequisites
            self.check_prerequisites()
            
            # Step 1: Convert text files to JSON, analyze binary files
            self.run_txt_to_json()
            
            # Step 2: Convert JSON to YARA
            self.run_transpile_to_yara()
            
            # Step 2.5: YARA Syntax Validation (always run)
            self.run_yara_syntax_validation()
            
            # Step 3: LLM validation (optional)
            if not skip_validation:
                self.run_llm_validation(output_file)
            
            # Validate outputs
            self.validate_outputs()
            
            logger.info("🎉 Pipeline completed successfully!")
            
        except Exception as e:
            logger.error(f"❌ Pipeline failed: {e}")
            raise

def main():
    parser = argparse.ArgumentParser(description="Run the complete YARA pipeline")
    parser.add_argument("--input", "-i", nargs="+", help="Input files to process")
    parser.add_argument("--data-dir", "-d", default="data", help="Data directory")
    parser.add_argument("--scripts-dir", "-s", default="scripts", help="Scripts directory")
    parser.add_argument("--skip-validation", action="store_true", help="Skip LLM validation")
    parser.add_argument("--output", "-o", help="Output file for validation results")
    
    args = parser.parse_args()
    
    try:
        # Initialize pipeline runner
        runner = PipelineRunner(
            data_dir=args.data_dir,
            scripts_dir=args.scripts_dir,
            input_files=args.input
        )
        
        # Run pipeline
        runner.run_pipeline(
            skip_validation=args.skip_validation,
            output_file=args.output
        )
        
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
