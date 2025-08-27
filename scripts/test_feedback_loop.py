#!/usr/bin/env python3
"""
Test YARA Feedback Loop
Demonstrates the complete validation -> revision -> revalidation cycle
"""

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime

def test_complete_feedback_loop():
    """Test the complete YARA feedback loop"""
    print("🔄 Testing Complete YARA Feedback Loop")
    print("=" * 50)
    
    # Step 1: Run YARA syntax validation
    print("\n🔍 Step 1: Running YARA Syntax Validation...")
    try:
        result = subprocess.run([
            sys.executable, "scripts/yara_syntax_validator.py",
            "data/yara_rules.yar"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("✅ Validation successful - all rules are valid")
            print("🎉 No revision needed!")
            return
        else:
            print("⚠️  Validation found syntax errors")
            print("📋 Errors found:")
            print(result.stderr if result.stderr else "Unknown validation errors")
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        return
    
    # Step 2: Run YARA rule revision
    print("\n🔧 Step 2: Running YARA Rule Revision...")
    try:
        # Find the latest validation file
        validation_dir = Path("validation_results")
        if not validation_dir.exists():
            print("❌ No validation results directory found")
            return
        
        validation_files = list(validation_dir.glob("yara_validation_*.json"))
        if not validation_files:
            print("❌ No validation files found")
            return
        
        latest_validation = max(validation_files, key=lambda f: f.stat().st_mtime)
        print(f"📋 Using validation file: {latest_validation}")
        
        result = subprocess.run([
            sys.executable, "scripts/yara_rule_revision.py",
            str(latest_validation),
            "data/yara_rules.yar"
        ], capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print("✅ Rule revision completed")
            print("📋 Revision output:")
            print(result.stdout)
        else:
            print("⚠️  Rule revision had issues")
            print("📋 Revision errors:")
            print(result.stderr if result.stderr else "Unknown revision errors")
    except Exception as e:
        print(f"❌ Rule revision failed: {e}")
        return
    
    # Step 3: Re-validate after revision
    print("\n🔍 Step 3: Re-validating After Revision...")
    try:
        result = subprocess.run([
            sys.executable, "scripts/yara_syntax_validator.py",
            "data/yara_rules.yar"
        ], capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print("🎉 SUCCESS! All rules are now valid after revision")
        else:
            print("⚠️  Some rules still have issues after revision")
            print("📋 Remaining errors:")
            print(result.stderr if result.stderr else "Unknown validation errors")
    except Exception as e:
        print(f"❌ Re-validation failed: {e}")
        return
    
    print("\n🔄 Feedback Loop Test Complete!")

def show_feedback_loop_architecture():
    """Show the architecture of the feedback loop"""
    print("\n🏗️  YARA Feedback Loop Architecture")
    print("=" * 50)
    print("""
┌─────────────────────────────────────────────────────────────────┐
│                    YARA FEEDBACK LOOP                          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                STEP 1: YARA GENERATION                         │
│  • LLM generates YARA rules from file analysis                │
│  • Rules may contain syntax errors                            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│              STEP 2: NATIVE YARA VALIDATION                    │
│  • Use yara command to validate syntax                        │
│  • Extract individual rules and check each                    │
│  • Store detailed error feedback                              │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
        ┌─────────────────────┐     ┌─────────────────────┐
        │   VALIDATION OK     │     │  VALIDATION FAILED  │
        │  • Rules ready      │     │  • Syntax errors    │
        │  • No action needed │     │  • Send to LLM      │
        └─────────────────────┘     └─────────────────────┘
                    │                           │
                    │                           ▼
                    │           ┌─────────────────────────────────┐
                    │           │        STEP 3: LLM REVISION     │
                    │           │  • Send error details to LLM    │
                    │           │  • Include original rule        │
                    │           │  • Request corrected version    │
                    │           └─────────────────────────────────┘
                    │                           │
                    │                           ▼
                    │           ┌─────────────────────────────────┐
                    │           │      STEP 4: RULE UPDATE        │
                    │           │  • Extract corrected rule       │
                    │           │  • Update YARA file             │
                    │           │  • Validate corrected rule      │
                    │           └─────────────────────────────────┘
                    │                           │
                    │                           ▼
                    │           ┌─────────────────────────────────┐
                    │           │      STEP 5: RE-VALIDATION      │
                    │           │  • Check if errors resolved     │
                    │           │  • Confirm rule validity        │
                    │           │  • Log improvement metrics      │
                    │           └─────────────────────────────────┘
                    │                           │
                    └───────────┬───────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                        OUTPUT                                  │
│  • Valid YARA rules ready for use                             │
│  • Detailed validation feedback stored                        │
│  • Revision history and metrics                               │
│  • Continuous improvement loop                                 │
└─────────────────────────────────────────────────────────────────┘
    """)

def main():
    parser = argparse.ArgumentParser(
        description="Test the complete YARA feedback loop"
    )
    parser.add_argument(
        "--architecture", "-a",
        action="store_true",
        help="Show feedback loop architecture"
    )
    
    args = parser.parse_args()
    
    if args.architecture:
        show_feedback_loop_architecture()
        return
    
    try:
        test_complete_feedback_loop()
    except KeyboardInterrupt:
        print("\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n💥 Test failed: {e}")

if __name__ == "__main__":
    import argparse
    main()
