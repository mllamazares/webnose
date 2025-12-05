import os
import sys
import json
import yaml
import time
import argparse
import requests
import re
import concurrent.futures
import shutil
import subprocess
from urllib.parse import urlparse
from tqdm import tqdm
from fake_useragent import UserAgent
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = """
       |     |
       |     |
      /       \\
     ( __   __ )
      '--'-;  ;
     _     |  |
__ /` ``""-;_ |
\\ '.;------. `\\      webnose v0.2
 | |    __..  |        by @sysrekt
 | \\.-''   _  |       https://mll.sh
 | |  ,-'-,   |
 |  \\__.-'    |
  \\    '.    /
   \\     \\  /
    '.      |
      )     |
"""

DEFAULT_REPO_URL = "https://github.com/mllamazares/webnose.git"
WEBNOSE_DIR = os.path.expanduser("~/.webnose")
REPO_DIR = WEBNOSE_DIR
DEFAULT_TEMPLATES_DIR = os.path.join(REPO_DIR, "smell_templates")

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

def print_colored(text, color=Colors.ENDC, bold=False):
    if bold:
        print(f"{Colors.BOLD}{color}{text}{Colors.ENDC}", file=sys.stderr)
    else:
        print(f"{color}{text}{Colors.ENDC}", file=sys.stderr)

def load_templates(templates_dir):
    templates = []
    if not os.path.exists(templates_dir):
        return templates
        
    for filename in os.listdir(templates_dir):
        if filename.endswith(".yaml") or filename.endswith(".yml"):
            try:
                with open(os.path.join(templates_dir, filename), 'r') as f:
                    template = yaml.safe_load(f)
                    if template:
                        templates.append(template)
            except Exception as e:
                print_colored(f"⚠️ Error loading template {filename}: {e}", Colors.WARNING)
    return templates

def run_command(command, cwd=None):
    try:
        subprocess.check_call(command, shell=True, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def download_templates():
    # Clean up existing directory to ensure git clone works
    if os.path.exists(WEBNOSE_DIR):
        try:
            shutil.rmtree(WEBNOSE_DIR)
        except Exception as e:
            print_colored(f"[-] Failed to clean up {WEBNOSE_DIR}: {e}", Colors.RED)
            return False
            
    os.makedirs(WEBNOSE_DIR, exist_ok=True)
    
    print_colored("[*] Cloning templates from GitHub...", Colors.BLUE)
    
    if run_command(f"git clone {DEFAULT_REPO_URL} {REPO_DIR}"):
        print_colored("[+] Templates downloaded successfully!", Colors.GREEN)
        return True
    else:
        print_colored("[-] Failed to download templates.", Colors.RED)
        return False

def update_templates():
    if not os.path.exists(REPO_DIR):
        print_colored("[-] Templates directory not found. Please run normally to download first.", Colors.RED)
        return

    print_colored("[*] Updating templates...", Colors.BLUE)
    if run_command("git pull", cwd=REPO_DIR):
        print_colored("[+] Templates updated successfully!", Colors.GREEN)
    else:
        print_colored("[-] Failed to update templates.", Colors.RED)

def update_script():
    print_colored("[*] Updating webnose script...", Colors.BLUE)
    if run_command("git pull"):
        print_colored("[+] Script updated successfully!", Colors.GREEN)
    else:
        print_colored("[-] Failed to update script.", Colors.RED)

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

def fetch_url(url, timeout=10, ua_strategy=None):
    try:
        ua_string = ""
        
        # Default to random if no strategy or empty strategy
        if not ua_strategy:
            try:
                ua = UserAgent()
                ua_string = ua.random
            except Exception:
                ua_string = 'Mozilla/5.0 (compatible; webnose/0.2)'
        elif ua_strategy.get('custom'):
            ua_string = ua_strategy['custom']
        elif ua_strategy.get('random'):
            try:
                ua = UserAgent()
                ua_string = ua.random
            except Exception:
                ua_string = 'Mozilla/5.0 (compatible; webnose/0.2)'
        else:
             # Fallback if strategy dict exists but is empty/false
            try:
                ua = UserAgent()
                ua_string = ua.random
            except Exception:
                ua_string = 'Mozilla/5.0 (compatible; webnose/0.2)'
        
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

def analyze_target(url, templates, timeout, ua_strategy):
    # Fetch
    data = fetch_url(url, timeout, ua_strategy)
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
            total_risk += float(risk)
            
    return {
        'url': url,
        'subdomain': extract_subdomain(url),
        'risk_score': round(total_risk, 2),
        'smell_count': len(detected_smells),
        'smells': detected_smells
    }

def generate_reports(entries, output_file, topn, silent=False):
    # Filter and Sort
    valid_entries = [e for e in entries if not e.get('error')]
    # Sort URLs by risk score (descending)
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

    # Sort Subdomains by risk score (descending)
    sorted_subdomains = dict(sorted(formatted_subdomains.items(), key=lambda item: item[1]['risk_score'], reverse=True))

    # Final Report Structure
    report = {
        'subdomains': sorted_subdomains,
        'urls': sorted_entries
    }
    
    if output_file:
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            if not silent:
                print_colored(f"\n[+] Report written to {output_file}", Colors.GREEN)
        except Exception as e:
            if not silent:
                print_colored(f"[-] Error writing report: {e}", Colors.RED)
    else:
        # Print to stdout
        print(json.dumps(report, indent=2))

def load_templates(templates_dir, tags=None):
    templates = []
    if not os.path.exists(templates_dir):
        return templates
        
    # Normalize tags
    target_tags = set()
    if tags:
        target_tags = set(t.strip().lower() for t in tags.split(','))

    for root, dirs, files in os.walk(templates_dir):
        for filename in files:
            if filename.endswith(('.yaml', '.yml')):
                filepath = os.path.join(root, filename)
                try:
                    with open(filepath, 'r') as f:
                        template = yaml.safe_load(f)
                        if template:
                            # Filter by tags if specified
                            if target_tags:
                                template_tags = set(t.lower() for t in template.get('info', {}).get('tags', []))
                                if not target_tags.intersection(template_tags):
                                    continue
                                    
                            template['id'] = template.get('id', os.path.splitext(filename)[0])
                            templates.append(template)
                except Exception as e:
                    print_colored(f"[-] Error loading template {filename}: {e}", Colors.RED)
    return templates

def main():
    parser = argparse.ArgumentParser(description="Webnose v0.2 - Modular Web Smells Scanner", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-i", "--input", help="File containing list of URLs")
    parser.add_argument("-t", "--templates", help=f"Directory containing smell templates (default: {DEFAULT_TEMPLATES_DIR})")
    parser.add_argument("-o", "--output", help="Output JSON report file")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent workers")
    parser.add_argument("--timeout", type=int, default=4, help="HTTP request timeout")
    parser.add_argument("--random-agent", action="store_true", help="Use random User-Agent")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("-s", "--silent", action="store_true", help="Suppress output")
    parser.add_argument("-ut", "--update-templates", action="store_true", help="Update smell templates from GitHub")
    parser.add_argument("-up", "--update-program", action="store_true", help="Update webnose script from GitHub")
    parser.add_argument("--tags", help="Filter templates by tags (comma-separated, e.g., 'security,legacy')")
    
    args = parser.parse_args()

    # Silent Mode
    if not args.silent:
        # Print Banner to stderr
        print(BANNER, file=sys.stderr)

    # Update Program
    if args.update_program:
        update_program()
        sys.exit(0)

    # Update Templates
    if args.update_templates:
        if download_templates():
            sys.exit(0)
        else:
            sys.exit(1)

    # Determine Templates Directory
    templates_dir = args.templates
    if not templates_dir:
        # Check if default exists
        if os.path.exists(DEFAULT_TEMPLATES_DIR):
            templates_dir = DEFAULT_TEMPLATES_DIR
        else:
            # Auto-download if missing
            if not args.silent:
                print_colored("[!] Templates not found. Downloading...", Colors.WARNING)
            
            if download_templates():
                templates_dir = DEFAULT_TEMPLATES_DIR
            else:
                if not args.silent:
                    print_colored("[-] Failed to download templates. Exiting.", Colors.RED)
                sys.exit(1)

    # Load Templates
    if not args.silent:
        print_colored(f"[+] Loading templates from {templates_dir}...", Colors.BLUE)
    
    templates = load_templates(templates_dir, args.tags)
    
    if not templates:
        if not args.silent:
            print_colored("[-] No templates found!", Colors.RED)
        sys.exit(1)
        
    if not args.silent:
        print_colored(f"[+] Loaded {len(templates)} templates", Colors.GREEN)

    # Load URLs
    urls = []
    try:
        if args.input:
            with open(args.input, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        elif not sys.stdin.isatty():
            urls = [line.strip() for line in sys.stdin if line.strip()]
        else:
            parser.print_help()
            sys.exit(1)
    except Exception as e:
        if not args.silent:
            print_colored(f"[-] Error reading input: {e}", Colors.RED)
        sys.exit(1)
        
    if not args.silent:
        print_colored(f"[+] Loaded {len(urls)} URLs to analyze", Colors.CYAN)
    
    # Analyze
    results = []
    if not args.silent:
        print_colored(f"[+] Starting analysis with {args.concurrency} workers...\n", Colors.BLUE, bold=True)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        # Determine UA strategy
        ua_strategy = {'random': args.random_agent, 'custom': args.user_agent}
        
        futures = {executor.submit(analyze_target, url, templates, args.timeout, ua_strategy): url for url in urls}
        
        if args.silent:
            for future in concurrent.futures.as_completed(futures):
                results.append(future.result())
        else:
            for future in tqdm(concurrent.futures.as_completed(futures), total=len(urls), unit="url"):
                results.append(future.result())
            
    # Generate Reports
    generate_reports(results, args.output, 10, args.silent)
    if not args.silent:
        print_colored("[+] Analysis completed", Colors.GREEN, bold=True)

if __name__ == "__main__":
    main()
