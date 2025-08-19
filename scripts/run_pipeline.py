#!/usr/bin/env python3
"""
YARA Pipeline Automation Script
Runs the complete pipeline: txt_to_json -> transpile_to_yara
"""

import os
import sys
import subprocess
import argparse
import logging
from pathlib import Path
from datetime import datetime

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
    def __init__(self, data_dir="data", scripts_dir="scripts"):
        self.data_dir = Path(data_dir)
        self.scripts_dir = Path(scripts_dir)
        self.workspace_root = Path(__file__).parent.parent
        
        # Ensure we're in the right directory
        os.chdir(self.workspace_root)
        
        # Define file paths
        self.input_file = self.data_dir / "signature_patterns.txt"
        self.json_file = self.data_dir / "signatures.json"
        self.yara_file = self.data_dir / "yara_rules.yar"
        
        # Script paths
        self.txt_to_json_script = self.scripts_dir / "txt_to_json.py"
        self.transpile_script = self.scripts_dir / "transpile_to_yara.py"
    
    def check_prerequisites(self):
        """Check if all required files and dependencies exist"""
        logger.info("🔍 Checking prerequisites...")
        
        # Check if input file exists
        if not self.input_file.exists():
            raise FileNotFoundError(f"Input file not found: {self.input_file}")
        
        # Check if scripts exist
        if not self.txt_to_json_script.exists():
            raise FileNotFoundError(f"txt_to_json.py script not found: {self.txt_to_json_script}")
        
        if not self.transpile_script.exists():
            raise FileNotFoundError(f"transpile_to_yara.py script not found: {self.transpile_script}")
        
        # Check if data directory exists
        if not self.data_dir.exists():
            raise FileNotFoundError(f"Data directory not found: {self.data_dir}")
        
        logger.info("✅ All prerequisites met")
    
    def run_txt_to_json(self):
        """Run the txt_to_json.py script"""
        logger.info("🔄 Step 1: Converting signature patterns to JSON...")
        
        cmd = [
            sys.executable,
            str(self.txt_to_json_script),
            str(self.input_file),
            "--output", str(self.json_file)
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=self.workspace_root,
                check=True
            )
            
            logger.info("✅ JSON conversion completed successfully")
            if result.stdout:
                logger.info(f"Output: {result.stdout.strip()}")
            
            # Verify output file was created
            if not self.json_file.exists():
                raise FileNotFoundError("JSON file was not created")
            
            logger.info(f"📁 JSON file created: {self.json_file}")
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ JSON conversion failed with exit code {e.returncode}")
            if e.stdout:
                logger.error(f"STDOUT: {e.stdout}")
            if e.stderr:
                logger.error(f"STDERR: {e.stderr}")
            raise
        except Exception as e:
            logger.error(f"❌ Unexpected error during JSON conversion: {e}")
            raise
    
    def run_transpile_to_yara(self):
        """Run the transpile_to_yara.py script"""
        logger.info("🔄 Step 2: Converting JSON to YARA rules...")
        
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
            
            logger.info("✅ YARA conversion completed successfully")
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
    
    def run_pipeline(self, clean=False):
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
            
            # Validate outputs
            self.validate_outputs()
            
            end_time = datetime.now()
            duration = end_time - start_time
            
            logger.info("🎉 Pipeline completed successfully!")
            logger.info(f"⏱️  Total duration: {duration}")
            logger.info(f"📁 Final outputs:")
            logger.info(f"   - JSON: {self.json_file}")
            logger.info(f"   - YARA: {self.yara_file}")
            
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
        logger.info(f"   Input file: {self.input_file} {'✅' if self.input_file.exists() else '❌'}")
        logger.info(f"   JSON file: {self.json_file} {'✅' if self.json_file.exists() else '❌'}")
        logger.info(f"   YARA file: {self.yara_file} {'✅' if self.yara_file.exists() else '❌'}")

def main():
    parser = argparse.ArgumentParser(
        description="Run the complete YARA pipeline: txt_to_json -> transpile_to_yara"
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
    
    try:
        runner = PipelineRunner(args.data_dir, args.scripts_dir)
        
        if args.status:
            runner.show_status()
            return
        
        runner.run_pipeline(clean=args.clean)
        
    except KeyboardInterrupt:
        logger.info("⏹️  Pipeline interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"💥 Pipeline failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
