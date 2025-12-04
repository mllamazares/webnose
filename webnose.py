#!/usr/bin/env python3
import os
import sys
import time
import argparse
import yaml
import json
import re
import requests
import concurrent.futures
from urllib.parse import urlparse
from tqdm import tqdm
from fake_useragent import UserAgent

# Disable SSL warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ASCII Art Banner
BANNER = r"""
      _.--.
    .'   ` '
     ``'.  .'     .c-..
        `.  ``````  .-'
       -'`. )--. .'`
       `-`._   \_`-- webnose v0.2 
                     by @sysrekt
                     https://linkedin.com/in/mllamazares
"""

# ANSI Color Codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_colored(text, color, bold=False):
    """Print text with color and optional bold formatting."""
    bold_code = Colors.BOLD if bold else ''
    print(f"{bold_code}{color}{text}{Colors.ENDC}")

def load_templates(directory):
    templates = []
    if not os.path.exists(directory):
        print_colored(f"❌ Template directory '{directory}' not found", Colors.RED)
        sys.exit(1)
        
    for filename in os.listdir(directory):
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            path = os.path.join(directory, filename)
            try:
                with open(path, 'r') as f:
                    template = yaml.safe_load(f)
                    if template:
                        templates.append(template)
            except Exception as e:
                print_colored(f"⚠️ Error loading template {filename}: {e}", Colors.WARNING)
    return templates

def extract_subdomain(url):
    parsed = urlparse(url)
    netloc = parsed.netloc
    if re.match(r'^\d+\.\d+\.\d+\.\d+', netloc):
        return netloc
    if ':' in netloc:
        netloc = netloc.split(':')[0]
    parts = netloc.split('.')
    if len(parts) <= 2:
        return netloc
    return netloc

def fetch_url(url, timeout=10, random_agent=False):
    try:
        ua_string = 'Mozilla/5.0 (compatible; webnose/0.2; +https://github.com/sysrekt/webnose)'
        if random_agent:
            try:
                ua = UserAgent()
                ua_string = ua.random
            except Exception:
                pass # Fallback to default if generation fails
        
        headers = {
            'User-Agent': ua_string
        }
        response = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        return {
            'url': url,
            'status_code': response.status_code,
            'body': response.text,
            'headers': response.headers,
            'error': None
        }
    except Exception as e:
        return {
            'url': url,
            'error': str(e)
        }

def count_smell_instances(content, template):
    matchers = template.get('matchers', [])
    if not matchers:
        return 0
        
    total_count = 0
        
    for matcher in matchers:
        m_type = matcher.get('type', 'regex')
        part = matcher.get('part', 'body')
        negative = matcher.get('negative', False)
        regexes = matcher.get('regex', [])
        case_insensitive = matcher.get('case_insensitive', True) # Default to True for backward compat
        
        # Determine target content
        target = ""
        if part == 'url':
            target = content.get('url', '')
        elif part == 'body':
            target = content.get('body', '')
        elif part == 'header':
            # Stringify headers for regex
            target = '\n'.join([f"{k}: {v}" for k, v in content.get('headers', {}).items()])
        elif part == 'all':
            headers = '\n'.join([f"{k}: {v}" for k, v in content.get('headers', {}).items()])
            target = f"{content.get('url', '')}\n{headers}\n{content.get('body', '')}"
            
        if not target:
            if negative: 
                total_count += 1
                continue
            if content.get('error'): return 0
            
        # Check regexes
        matcher_count = 0
        flags = re.MULTILINE
        if case_insensitive:
            flags |= re.IGNORECASE
            
        for regex in regexes:
            matches = re.findall(regex, target, flags)
            matcher_count += len(matches)
        
        if negative:
            if matcher_count > 0: return 0
            total_count += 1
        else:
            if matcher_count == 0: return 0
            total_count += matcher_count
            
    return total_count

def analyze_target(url, templates, timeout, random_agent):
    # Fetch
    data = fetch_url(url, timeout, random_agent)
    if data.get('error'):
        return {
            'url': url,
            'error': data['error'],
            'subdomain': extract_subdomain(url),
            'smell_count': 0,
            'risk_score': 0.0,
            'smells': {}
        }
        
    # Match
    detected_smells = {}
    total_risk = 0.0
    
    for template in templates:
        smell_id = template.get('id')
        count = count_smell_instances(data, template)
        if count > 0:
            detected_smells[smell_id] = count
            risk = template.get('info', {}).get('risk_score', 0.0)
            total_risk += (count * float(risk))
            
    return {
        'url': url,
        'subdomain': extract_subdomain(url),
        'risk_score': round(total_risk, 2),
        'smell_count': len(detected_smells),
        'smells': detected_smells
    }

def generate_reports(entries, output_file, topn):
    # Filter and Sort
    valid_entries = [e for e in entries if not e.get('error')]
    sorted_entries = sorted(valid_entries, key=lambda x: x.get('risk_score', 0), reverse=True)
    
    # Subdomain Aggregation
    subdomain_stats = {}
    for entry in valid_entries:
        sub = entry.get('subdomain', '')
        risk = entry.get('risk_score', 0)
        smell_count = entry.get('smell_count', 0)
        
        if sub not in subdomain_stats:
            subdomain_stats[sub] = {
                'total_risk': 0.0,
                'url_count': 0,
                'total_smells': 0,
                'max_risk': 0.0
            }
            
        stats = subdomain_stats[sub]
        stats['total_risk'] += risk
        stats['url_count'] += 1
        stats['total_smells'] += smell_count
        if risk > stats['max_risk']:
            stats['max_risk'] = risk
            
    # Format Subdomains
    formatted_subdomains = {}
    for sub, stats in subdomain_stats.items():
        formatted_subdomains[sub] = {
            'risk_score': round(stats['total_risk'], 2),
            'avg_risk': round(stats['total_risk'] / stats['url_count'], 2) if stats['url_count'] else 0,
            'max_risk': round(stats['max_risk'], 2),
            'url_count': stats['url_count'],
            'total_smells': stats['total_smells']
        }

    # Final Report Structure
    report = {
        'subdomains': formatted_subdomains,
        'urls': sorted_entries
    }
    
    try:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print_colored(f"\n[+] Report written to {output_file}", Colors.GREEN)
    except Exception as e:
        print_colored(f"[-] Error writing report: {e}", Colors.RED)


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Webnose v0.2 - Modular Web Smells Scanner")
    parser.add_argument("-i", "--input", required=True, help="File containing list of URLs")
    parser.add_argument("-t", "--templates", default="smells_templates", help="Directory containing smell templates")
    parser.add_argument("-o", "--output", default="webnose_report.json", help="Output JSON report file")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Number of concurrent workers")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP request timeout")
    parser.add_argument("--random-agent", action="store_true", help="Use random User-Agent")
    args = parser.parse_args()

    # Load Templates
    print_colored(f"[+] Loading templates from {args.templates}...", Colors.BLUE)
    templates = load_templates(args.templates)
    print_colored(f"[+] Loaded {len(templates)} templates", Colors.CYAN)

    # Load URLs
    try:
        with open(args.input, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_colored(f"[-] Error reading input file: {e}", Colors.RED)
        sys.exit(1)
        
    print_colored(f"[+] Loaded {len(urls)} URLs to analyze", Colors.CYAN)
    
    # Analyze
    results = []
    print_colored(f"[+] Starting analysis with {args.workers} workers...\n", Colors.BLUE, bold=True)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(analyze_target, url, templates, args.timeout, args.random_agent): url for url in urls}
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(urls), unit="url"):
            results.append(future.result())
            
    # Generate Reports
    generate_reports(results, args.output, 10)
    print_colored("[+] Analysis completed", Colors.GREEN, bold=True)

if __name__ == "__main__":
    main()
