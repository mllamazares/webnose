import os
import yaml

TEMPLATE_DIR = "smell_templates"

# Mapping of ID to elaborated description
DESCRIPTIONS = {
    "CDATA": "Detects the presence of CDATA sections, which may indicate XML parsing or potential XSS vectors in older browsers.",
    "IE_browser_hack": "Identifies conditional comments or hacks specific to Internet Explorer, suggesting legacy code support.",
    "NUXT": "Detects the presence of Nuxt.js framework signatures in the response.",
    "adhoc_ajax": "Finds ad-hoc AJAX requests (XMLHttpRequest) constructed in scripts, often interesting for API discovery.",
    "coming_soon": "Identifies 'Coming Soon' or placeholder pages, which might be low-hanging fruit or unmaintained.",
    "console_debugging": "Detects 'console.log' or other console debugging statements left in production code.",
    "cors_star": "Checks for 'Access-Control-Allow-Origin: *' header, indicating a potentially insecure CORS configuration.",
    "dangerous_functions": "Scans for dangerous JavaScript functions like 'eval()', 'setTimeout()', or 'innerHTML' usage.",
    "deserialization": "Looks for keywords related to object deserialization (e.g., Java, PHP, Python), a common vulnerability class.",
    "disabled_button": "Finds disabled HTML buttons, which might be bypassable or hide functionality.",
    "event_handlers": "Detects inline HTML event handlers (e.g., onclick, onmouseover), often used in XSS payloads.",
    "fileupload": "Identifies file upload forms or inputs, a critical functionality to test for vulnerabilities.",
    "get_params": "Detects URLs with GET parameters, which are primary injection points for SQLi, XSS, etc.",
    "graphql": "Detects GraphQL endpoints or error messages, indicating a GraphQL API is in use.",
    "hardcoded_style": "Finds inline 'style=' attributes, which might indicate poor coding practices or injection points.",
    "html_newlines": "Detects raw newline characters in HTML, potentially interesting for formatting or injection issues.",
    "huge_content_length": "Flags responses with unusually large Content-Length, which might be data leaks or large assets.",
    "interesting_attrs": "Scans for interesting HTML attributes like 'data-*', 'hidden', or custom attributes.",
    "interesting_tech": "Identifies various interesting technologies or frameworks based on keywords.",
    "juicy_url": "Flags URLs containing keywords like 'admin', 'config', 'backup', 'test', etc.",
    "localhost": "Detects references to 'localhost' or '127.0.0.1', potentially leaking internal dev environment details.",
    "no_cms": "Matches when common CMS signatures are ABSENT, suggesting a custom application.",
    "nowaf": "Matches when common WAF signatures are ABSENT, indicating the target might be unprotected.",
    "signup": "Identifies sign-up or registration pages, a key entry point for user enumeration or logic bugs.",
    "spaces_in_url": "Detects spaces in URLs, which is non-standard and might cause parsing issues.",
    "suspicious_cookies": "Flags cookies with suspicious names like 'admin', 'debug', 'test', or missing secure flags.",
    "url_ip": "Detects IP addresses used directly in URLs instead of domain names.",
    "vintage_DOCTYPE": "Identifies older DOCTYPE declarations (e.g., HTML 4.01), suggesting legacy applications.",
    "vintage_tags": "Detects deprecated HTML tags like <marquee>, <blink>, or <font>.",
    "weird_port": "Flags URLs using non-standard ports (not 80 or 443)."
}

def update_templates():
    if not os.path.exists(TEMPLATE_DIR):
        print(f"Directory {TEMPLATE_DIR} not found")
        return

    for filename in os.listdir(TEMPLATE_DIR):
        if not filename.endswith(".yaml"):
            continue
            
        path = os.path.join(TEMPLATE_DIR, filename)
        
        with open(path, 'r') as f:
            content = yaml.safe_load(f)
            
        smell_id = content.get('id')
        
        # Reorder Info
        if 'info' in content:
            old_info = content['info']
            new_info = {}
            
            # Get new description or keep old
            desc = DESCRIPTIONS.get(smell_id, old_info.get('description', ''))
            
            # Force order: description, author, risk_score, others
            new_info['description'] = desc
            if 'author' in old_info: new_info['author'] = old_info['author']
            if 'risk_score' in old_info: new_info['risk_score'] = old_info['risk_score']
            
            # Add remaining keys
            for k, v in old_info.items():
                if k not in ['description', 'author', 'risk_score']:
                    new_info[k] = v
                    
            content['info'] = new_info
            
        with open(path, 'w') as f:
            yaml.dump(content, f, sort_keys=False, indent=2)
            print(f"Updated {filename}")

if __name__ == "__main__":
    update_templates()
