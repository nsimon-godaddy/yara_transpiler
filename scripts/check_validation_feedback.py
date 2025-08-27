#!/usr/bin/env python3
"""
YARA Validation Feedback Checker
Demonstrates how to retrieve and use stored validation feedback
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List

def get_latest_validation_results(validation_dir: str = "validation_results") -> Dict:
    """Get the latest YARA validation results"""
    validation_path = Path(validation_dir)
    
    if not validation_path.exists():
        print(f"❌ Validation directory not found: {validation_dir}")
        return {}
    
    # Find the most recent validation file
    validation_files = list(validation_path.glob("yara_validation_*.json"))
    if not validation_files:
        print(f"❌ No validation files found in {validation_dir}")
        return {}
    
    # Sort by modification time and get the latest
    latest_file = max(validation_files, key=lambda f: f.stat().st_mtime)
    
    try:
        with open(latest_file, 'r', encoding='utf-8') as f:
            results = json.load(f)
        
        results['validation_file'] = str(latest_file)
        return results
        
    except Exception as e:
        print(f"❌ Could not load validation results from {latest_file}: {e}")
        return {}

def analyze_validation_feedback(results: Dict) -> Dict:
    """Analyze validation feedback and provide actionable insights"""
    analysis = {
        'summary': {},
        'issues': [],
        'recommendations': [],
        'rule_details': {}
    }
    
    if not results:
        return analysis
    
    # Overall summary
    analysis['summary'] = {
        'file': results.get('file', 'Unknown'),
        'overall_valid': results.get('valid', False),
        'total_rules': len(results.get('rules', [])),
        'valid_rules': sum(1 for rule in results.get('rules', []) if rule.get('valid', False)),
        'invalid_rules': sum(1 for rule in results.get('rules', []) if not rule.get('valid', False)),
        'timestamp': results.get('timestamp', 'Unknown')
    }
    
    # Analyze each rule
    for rule in results.get('rules', []):
        rule_name = rule.get('name', 'Unknown')
        rule_analysis = {
            'valid': rule.get('valid', False),
            'errors': rule.get('errors', []),
            'warnings': rule.get('warnings', []),
            'line_range': f"{rule.get('line_start', '?')}-{rule.get('line_end', '?')}",
            'content_preview': rule.get('content_preview', '')[:100] + '...' if len(rule.get('content_preview', '')) > 100 else rule.get('content_preview', '')
        }
        
        analysis['rule_details'][rule_name] = rule_analysis
        
        # Collect common issues
        if not rule.get('valid', False):
            for error in rule.get('errors', []):
                if 'undefined identifier' in error:
                    analysis['issues'].append({
                        'type': 'undefined_identifier',
                        'rule': rule_name,
                        'error': error,
                        'recommendation': 'Check for typos or undefined variables in the condition'
                    })
                elif 'syntax error' in error:
                    analysis['issues'].append({
                        'type': 'syntax_error',
                        'rule': rule_name,
                        'error': error,
                        'recommendation': 'Check YARA syntax, especially brackets, quotes, and semicolons'
                    })
                elif 'unterminated' in error:
                    analysis['issues'].append({
                        'type': 'unterminated',
                        'rule': rule_name,
                        'error': error,
                        'recommendation': 'Check for missing closing brackets, quotes, or parentheses'
                    })
                else:
                    analysis['issues'].append({
                        'type': 'other',
                        'rule': rule_name,
                        'error': error,
                        'recommendation': 'Review the rule syntax and structure'
                    })
    
    # Generate recommendations
    if analysis['summary']['invalid_rules'] > 0:
        analysis['recommendations'].append({
            'priority': 'high',
            'action': 'Fix syntax errors before using rules',
            'details': f"{analysis['summary']['invalid_rules']} rule(s) have syntax errors"
        })
    
    if analysis['summary']['valid_rules'] > 0:
        analysis['recommendations'].append({
            'priority': 'medium',
            'action': 'Test valid rules against sample files',
            'details': f"{analysis['summary']['valid_rules']} rule(s) are syntactically correct"
        })
    
    return analysis

def print_analysis(analysis: Dict):
    """Print the analysis results in a readable format"""
    print("\n" + "="*70)
    print("🔍 YARA VALIDATION FEEDBACK ANALYSIS")
    print("="*70)
    
    # Summary
    summary = analysis['summary']
    print(f"📁 File: {summary['file']}")
    print(f"✅ Overall Status: {'VALID' if summary['overall_valid'] else 'INVALID'}")
    print(f"📊 Rules: {summary['total_rules']} total, {summary['valid_rules']} valid, {summary['invalid_rules']} invalid")
    print(f"⏰ Timestamp: {summary['timestamp']}")
    
    # Issues
    if analysis['issues']:
        print(f"\n❌ ISSUES FOUND ({len(analysis['issues'])}):")
        print("-" * 50)
        for i, issue in enumerate(analysis['issues'], 1):
            print(f"{i}. {issue['type'].upper()} in rule '{issue['rule']}':")
            print(f"   Error: {issue['error']}")
            print(f"   Recommendation: {issue['recommendation']}")
            print()
    
    # Rule details
    if analysis['rule_details']:
        print(f"📋 RULE DETAILS:")
        print("-" * 50)
        for rule_name, details in analysis['rule_details'].items():
            status = "✅ VALID" if details['valid'] else "❌ INVALID"
            print(f"{status} | {rule_name} (lines {details['line_range']})")
            
            if not details['valid']:
                for error in details['errors']:
                    print(f"    ❌ {error}")
            
            if details['content_preview']:
                print(f"    📝 Preview: {details['content_preview']}")
            print()
    
    # Recommendations
    if analysis['recommendations']:
        print(f"💡 RECOMMENDATIONS:")
        print("-" * 50)
        for i, rec in enumerate(analysis['recommendations'], 1):
            priority_icon = "🔴" if rec['priority'] == 'high' else "🟡" if rec['priority'] == 'medium' else "🟢"
            print(f"{i}. {priority_icon} {rec['action']}")
            print(f"   {rec['details']}")
            print()

def main():
    parser = argparse.ArgumentParser(
        description="Check and analyze YARA validation feedback"
    )
    parser.add_argument(
        "--validation-dir", "-d",
        default="validation_results",
        help="Directory containing validation results"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for analysis results (JSON)"
    )
    
    args = parser.parse_args()
    
    try:
        # Get latest validation results
        results = get_latest_validation_results(args.validation_dir)
        
        if not results:
            print("❌ No validation results found")
            return
        
        # Analyze the feedback
        analysis = analyze_validation_feedback(results)
        
        # Print analysis
        print_analysis(analysis)
        
        # Save analysis if requested
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(analysis, f, indent=2, ensure_ascii=False)
            print(f"💾 Analysis saved to: {args.output}")
        
        # Exit with appropriate code
        if analysis['summary']['overall_valid']:
            print("🎉 All YARA rules are syntactically valid!")
            exit(0)
        else:
            print("⚠️  Some YARA rules have syntax errors. Check the analysis above.")
            exit(1)
        
    except Exception as e:
        print(f"💥 Analysis failed: {e}")
        exit(1)

if __name__ == "__main__":
    main()
