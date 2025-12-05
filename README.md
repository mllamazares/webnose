# 👃 webnose

**webnose** is a modular, concurrent web scanner designed to sniff out "smells" (security characteristics, interesting tech, or potential vulnerabilities) in web applications. It uses a flexible YAML-based template system to define checks, making it easy to extend and customize.

## Features

-   **Modular Design**: All checks are defined in simple YAML templates.
-   **Concurrent Scanning**: Fast analysis of multiple URLs using thread pools.
-   **Risk Scoring**: Calculates a risk score for each URL based on detected smells.
-   **Detailed Reporting**: Generates a comprehensive JSON report with subdomain aggregation.
-   **Random User-Agent**: Built-in evasion with random User-Agent strings.
-   **Instance Counting**: Reports exactly how many times a smell pattern was found.

## Installation

Ensure you have Go installed (1.21+).

```bash
go install github.com/mllamazares/webnose@latest
```

## Usage

```bash
# Scan a single URL
webnose -t http://example.com

# Scan a list of URLs from a file
webnose -t urls.txt

# Scan a list of domains (auto-adds https/http)
webnose -t domains.txt

# Filter by tags
webnose -t urls.txt --tags security,legacy

# Save output to JSON
webnose -t urls.txt -o report.json
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t` | Target URL or file containing targets | (Required) |
| `-o` | Output JSON report file | stdout |
| `-c` | Number of concurrent workers | 10 |
| `--timeout` | HTTP request timeout (seconds) | 4 |
| `--tags` | Filter templates by tags (comma-separated) | All |
| `--templates-dir` | Directory containing smell templates | `~/.webnose/smell_templates` |
| `-s` | Silent mode (suppress logs) | False |

### Examples

**Basic Scan:**
```bash
webnose -i targets.txt -c 20 -o report.json
```

**Pipe Input & Silent Output:**
```bash
cat targets.txt | webnose -s > report.json
```

**Update Templates:**
```bash
webnose -ut
```

## Template Management

By default, `webnose` looks for templates in `~/.webnose/repo/smell_templates`. If not found, it will prompt you to download them automatically. You can update them at any time using the `-ut` flag.

## Creating Templates

Templates are YAML files located in `smell_templates/`. Example:

```yaml
id: my_smell
info:
  description: Detects my custom smell
  author: yourname
  risk_score: 5.0
matchers:
  - type: regex
    part: body  # url, body, header, all
    regex:
      - 'pattern_to_match'
    case_insensitive: true
```

## License

MIT License
