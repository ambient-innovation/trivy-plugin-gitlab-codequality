#!/usr/bin/env python3

import json
import sys
import argparse

LOG_PREFIX = "[trivy][plugins][codeclimate]"

SEVERITY_MAP = {"LOW": "info", "MEDIUM": "minor", "HIGH": "major", "CRITICAL": "critical", "UNKNOWN": "blocker"}

DEFAULT_SEVERITY = ['UNKNOWN','CRITICAL','HIGH']

DEFAULT_PKG_TYPES = ['os', 'library']

DEBUG = False

def main():
    global DEBUG
    parser = argparse.ArgumentParser(prog='gitlab-codeclimate')
    parser.add_argument('--severity',
                        type=lambda x: x.split(','),
                        default=DEFAULT_SEVERITY,
                        help='Global Severity (Default)')
    parser.add_argument('--severity-license',
                        type=lambda x: x.split(','),
                        help='License Severity')
    parser.add_argument('--severity-vuln',
                        type=lambda x: x.split(','),
                        help='Vulnerabilities Severity')
    parser.add_argument('--severity-misconfig',
                        type=lambda x: x.split(','),
                        help='Misconfig Severity')
    parser.add_argument('--severity-secret',
                        type=lambda x: x.split(','),
                        help='Secret Severity')
    parser.add_argument('--pkg-types',
                        type=lambda x: x.split(','),
                        default=DEFAULT_PKG_TYPES,
                        help='Global Package Types (Default)')
    parser.add_argument('--pkg-types-license',
                        type=lambda x: x.split(','),
                        help='License Package Types')
    parser.add_argument('--pkg-types-vuln',
                        type=lambda x: x.split(','),
                        help='Vulnerabilities Package Types')
    parser.add_argument('--pkg-types-misconfig',
                        type=lambda x: x.split(','),
                        help='Misconfig Package Types')
    parser.add_argument('--pkg-types-secret',
                        type=lambda x: x.split(','),
                        help='Secret Package Types')
    parser.add_argument('--debug',
                        action='store_true',
                        help='Debug Outputs')
    parser.add_argument('-o', '--output',
                        type=str,
                        default=None,
                        help='Output file')
    parser.add_argument('-i', '--input',
                        type=str,
                        default=None,
                        help='Input file')
    args = parser.parse_args()

    SEVERITY = build_severity_matrix(args)
    PKG_TYPES = build_pkg_types_matrix(args)

    if args.debug:
        DEBUG = True

    data = ""
    if args.input:
        with open(args.input, 'r') as infile:
            data = infile.read()
    else:
        for line in sys.stdin:
            data += line.rstrip()

    try:
        output = []
        data = json.loads(data)
        scan_groups = split_json(data)
        if DEBUG:
            print(f"{LOG_PREFIX} Scan Groups:")
            print(json.dumps(scan_groups, indent=2))
        for key, scan in scan_groups.items():
           output += filter_scan(scan, key, SEVERITY[key], PKG_TYPES[key])
        if DEBUG:
            print(f"{LOG_PREFIX} Output:")
            print(json.dumps(output, indent=2))
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(output, f, indent=4)
        else:
            print(json.dumps(output, indent=4))
    except json.decoder.JSONDecodeError:
        print(f"{LOG_PREFIX} Error: Invalid JSON data")
        exit(1)


def build_severity_matrix(args):
    severity_matrix = {
        "severity": args.severity,
        "license": args.severity_license or args.severity,
        "vuln": args.severity_vuln or args.severity,
        "misconfig": args.severity_misconfig or args.severity,
        "secret": args.severity_secret or args.severity
    }
    return severity_matrix

def build_pkg_types_matrix(args):
    pkg_types_matrix = {
        "pkg_types": args.pkg_types,
        "license": args.pkg_types_license or args.pkg_types,
        "vuln": args.pkg_types_vuln or args.pkg_types,
        "misconfig": args.pkg_types_misconfig or args.pkg_types,
        "secret": args.pkg_types_secret or args.pkg_types
    }
    return pkg_types_matrix

def split_json(data):
    # Define the mapping of result types to their keys and default values
    result_types = {
        "Vulnerabilities": ("vuln", "vuln_results"),
        "Misconfigurations": ("misconfig", "misconfig_results"),
        "Licenses": ("license", "license_results"),
        "Secrets": ("secret", "secrets_results")
    }

    # Initialize result containers
    results = {result_var: [] for _, result_var in result_types.values()}

    # Helper function to process items and add metadata
    def process_items(items, result, item_type):
        for item in items:
            item['Target'] = result.get('Target', item_type)
            item['Class'] = item.get('Class', item_type)
            item['Type'] = result.get('Type', item_type)
        return items

    # Process Results array
    for result in data.get("Results", []):
        for result_key, (item_type, result_var) in result_types.items():
            if (items := result.get(result_key)) is not None:
                processed_items = process_items(items, result, item_type)
                results[result_var].extend(processed_items)
                break  # Only process one type per result to maintain elif behavior

    return {
        "vuln": results["vuln_results"],
        "misconfig": results["misconfig_results"],
        "license": results["license_results"],
        "secret": results["secrets_results"]
    }

def get_package_type(item):
    """
    Determine if this is an OS package or library package based on Trivy output fields.
    Returns 'os' for operating system packages, 'library' for language/library packages.
    """
    # Check for Class field which indicates package type in Trivy output
    pkg_class = item.get('Class', '').lower()

    # Primary classification based on Class field
    if pkg_class == 'os-pkgs':
        return 'os'
    elif pkg_class == 'lang-pkgs':
        return 'library'

    # For license issues, check the Target field to determine if it's OS or language related
    if pkg_class == 'license':
        target = item.get('Target', '').lower()
        if target == 'os packages':
            return 'os'
        elif target in ['node.js', 'python', 'java', 'ruby', 'conda']:
            return 'library'
        # For other license targets, default to library
        return 'library'

    # Fallback: check Target field for OS-related indicators
    target = item.get('Target', '').lower()
    if any(os_indicator in target for os_indicator in ['debian', 'ubuntu', 'centos', 'rhel', 'alpine', 'suse', 'fedora']):
        return 'os'

    # Last resort: check FilePath for language-specific file extensions
    file_path = item.get('PkgPath', item.get('FilePath', ''))
    if file_path and any(ext in file_path.lower() for ext in ['.py', '.js', '.go', '.java', '.rb', '.php', '.rs', 'requirements.txt', 'package.json', 'go.mod', 'pom.xml', 'composer.json', 'cargo.toml']):
        return 'library'

    # Default to library if we can't determine (most issues are typically in dependencies)
    return 'library'

def build_content(item, issue_type):
    """Build content description based on issue type and available fields."""
    if issue_type == "license":
        fields = ['Name', 'PkgName', 'FilePath']
    elif issue_type == "misconfig":
        fields = ['Title', 'Target', 'Description', 'Message', 'Resolution', 'PrimaryURL']
    elif issue_type == "vuln":
        fields = ['VulnerabilityID', 'PkgID', 'Description', 'PrimaryURL']
    elif issue_type == "secret":
        fields = ['Title', 'Target', 'Match']
    else:
        fields = ['Description']

    desc_parts = []
    for field in fields:
        if field_value := item.get(field):
            desc_parts.append(field_value)
    return "\n".join(desc_parts)

def should_include_item(item, severity, pkg_types):
    """Check if an item should be included based on severity and package type filters."""
    # Check severity filter
    if item.get("Severity") not in severity:
        if DEBUG:
            print(f"{LOG_PREFIX} Filtering out {item.get('Severity')} package: {item.get('PkgName', item.get('Target', 'UNKNOWN'))}")
        return False

    # Check package type filter
    item_pkg_type = get_package_type(item)
    if item_pkg_type not in pkg_types:
        if DEBUG:
            print(f"{LOG_PREFIX} Filtering out {item_pkg_type} package: {item.get('PkgName', item.get('Target', 'UNKNOWN'))}")
        return False

    return True

def create_output_item(item, issue_type):
    """Create a standardized output item from a Trivy result."""
    return {
        "check_name": issue_type,
        "description": item.get('PkgId', item.get('PkgName', item.get('Target', "UNKNOWN"))),
        "fingerprint": build_content(item, issue_type),
        "severity": SEVERITY_MAP.get(item.get("Severity"), "info"),
        "categories": "Security",
        "location": {
            "path": item.get("PkgPath", item.get("FilePath", item.get("PkgID", item.get("Target", "UNKNOWN")))),
        }
    }

def filter_scan(result, issue_type, severity, pkg_types):
    if DEBUG:
        print(f"{LOG_PREFIX} Issue Type: {issue_type} Severity: {severity} Package Types: {pkg_types}")

    # Filter and transform items
    filtered_items = []
    for item in result:
        if should_include_item(item, severity, pkg_types):
            filtered_items.append(create_output_item(item, issue_type))

    return filtered_items


if __name__ == "__main__":
    main()