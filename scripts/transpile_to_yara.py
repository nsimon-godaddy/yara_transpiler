import json
import re
import argparse
import sys

def sanitize_rule_name(name):
    return re.sub(r'[^a-zA-Z0-9_]', '_', name)

def yara_escape_string(s):
    return s.replace('\\', '\\\\').replace('"', '\\"')

def cleanup_pattern_to_regex(pattern):
    """
    Convert cleanup_pattern (~regex~flags) into a safe YARA regex string.
    Escapes forward slashes, strips invalid constructs for YARA, and ensures it's closed.
    """
    m = re.match(r"~(.+)~([a-zA-Z]*)", pattern)
    if m:
        regex_body, flags = m.groups()
    else:
        regex_body, flags = pattern.strip("~"), ""

    # Escape forward slashes to avoid breaking /.../
    regex_body = regex_body.replace("/", r"\/")

    # Remove unsupported PCRE constructs from YARA (like backreferences)
    regex_body = re.sub(r"\\\d+", "", regex_body)

    # Avoid mixed greedy/ungreedy quantifiers (*? / +? / {x,}? with greedy ones)
    regex_body = re.sub(r"(\*\?|\+\?|\{\d*,\}\?)", ".*", regex_body)

    # Ensure regex is not empty
    if not regex_body.strip():
        regex_body = "."

    nocase = " nocase" if 'i' in flags else ""
    return f"/{regex_body}/{nocase}"

def generate_yara_rule(sig):
    rule_name = sanitize_rule_name(sig["name"])
    strings = []

    # Full chain strings
    for i, s in enumerate(sig.get("full_chain", [])):
        s_escaped = yara_escape_string(s)
        strings.append(f'    $fullchain{i} = "{s_escaped}" ascii')

    

    strings_section = "\n".join(strings)

    # For now, only require fullchain matches
    condition = "all of ($fullchain*)"

    rule = f"""rule {rule_name}
{{
    meta:
        description = "Converted from JSON signature {sig['name']}"

    strings:
{strings_section}

    condition:
        {condition}
}}
"""
    return rule

def convert_json_to_yara(json_path, output_path):
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    rules = [generate_yara_rule(sig) for sig in data.get("signatures", [])]
    yara_rules_text = "\n".join(rules)

    with open(output_path, "w", encoding="utf-8") as f_out:
        f_out.write(yara_rules_text)

    print(f"Converted {len(rules)} signatures to YARA rules in '{output_path}'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert JSON signatures to YARA rules.")
    parser.add_argument("json_path", help="Path to the input JSON file")
    parser.add_argument("output_path", help="Path to the output YARA file")
    args = parser.parse_args()

    convert_json_to_yara(args.json_path, args.output_path)
