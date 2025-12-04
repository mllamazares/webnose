# Webnose

**Webnose** is a modular, concurrent web scanner designed to sniff out "smells" (security characteristics, interesting tech, or potential vulnerabilities) in web applications. It uses a flexible YAML-based template system to define checks, making it easy to extend and customize.

## Features

-   **Modular Design**: All checks are defined in simple YAML templates.
-   **Concurrent Scanning**: Fast analysis of multiple URLs using thread pools.
-   **Risk Scoring**: Calculates a risk score for each URL based on detected smells.
-   **Detailed Reporting**: Generates a comprehensive JSON report with subdomain aggregation.
-   **Random User-Agent**: Built-in evasion with random User-Agent strings.
-   **Instance Counting**: Reports exactly how many times a smell pattern was found.

## Installation

### Using pipx (Recommended)

To install `webnose` in an isolated environment and make it available globally:

```bash
pipx install git+https://github.com/mllamazares/webnose.git
```

### From Source

1.  Clone the repository:
    ```bash
    git clone https://github.com/mllamazares/webnose.git
    cd webnose
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

```bash
webnose [options]
```

### Options

-   `-i, --input <file>`: File containing list of URLs (optional, reads from stdin if omitted).
-   `-t, --templates <dir>`: Directory containing smell templates (default: `~/.webnose/repo/smell_templates`).
-   `-o, --output <file>`: Output JSON report file (optional, prints to stdout if omitted).
-   `-c, --concurrency <int>`: Number of concurrent workers (default: 10).
-   `--timeout <int>`: HTTP request timeout in seconds (default: 10).
-   `--random-agent`: Use a random User-Agent string.
-   `--user-agent <string>`: Use a custom User-Agent string.
-   `-s, --silent`: Suppress banners and logs (JSON output only).
-   `-ut, --update-templates`: Update smell templates from GitHub.
-   `-up, --update-program`: Update webnose script from GitHub.

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
