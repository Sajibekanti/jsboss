import requests
import re
import argparse
import json
import signal
import sys
import os
from urllib.parse import urlparse
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    banner = r"""
   ___  _____ ______  _____  _____  _____ 
  |_  |/  ___|| ___ \|  _  |/  ___|/  ___|
    | |\ `--. | |_/ /| | | |\ `--. \ `--. 
    | | `--. \| ___ \| | | | `--. \ `--. \
/\__/ //\__/ /| |_/ /\ \_/ //\__/ //\__/ /
\____/ \____/ \____/  \___/ \____/ \____/ 

    """
    
    terminal_width = os.get_terminal_size().columns
    banner_lines = banner.strip().splitlines()

    for i, line in enumerate(banner_lines):
        if i % 4 == 0:
            color = Fore.MAGENTA  # Purple
        elif i % 4 == 1:
            color = Fore.LIGHTMAGENTA_EX  # Pink
        elif i % 4 == 2:
            color = Fore.YELLOW  # Yellow
        else:
            color = Fore.LIGHTYELLOW_EX  # Orange
        print(color + line.center(terminal_width))

    quote = f"{Fore.CYAN}JSBOSS - \"Juicy Secrets in JavaScript!\"{Style.RESET_ALL}"
    print(quote.center(terminal_width))

def extract_links_from_js(js_content):
    url_pattern = r'(https?://[^\s\'"<>]+)'
    return re.findall(url_pattern, js_content)

def extract_secrets(js_content):
    
    secret_patterns = {
    # Amazon Web Services (AWS)
    'AWS Access Key': r'(?i)aws_access_key_id\s*[:=]\s*[\'"]?([A-Z0-9]{20})[\'"]?',
    'AWS Secret Key': r'(?i)aws_secret_access_key\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?',
    'AWS Session Token': r'(?i)aws_session_token\s*[:=]\s*[\'"]?([A-Za-z0-9/+=]{16,})[\'"]?',

    # Google Cloud
    'Google Cloud API Key': r'(?i)AIza[0-9A-Za-z-_]{35}',
    'Google OAuth Access Token': r'ya29\.[0-9A-Za-z\-_]+',
    'Google Cloud Secret Key': r'(?i)"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----[A-Za-z0-9/+=\s]+-----END PRIVATE KEY-----"',

    # Azure
    'Azure Tenant ID': r'(?i)azure_tenant_id\s*[:=]\s*[\'"]?([0-9a-fA-F\-]{36})[\'"]?',
    'Azure Client ID': r'(?i)azure_client_id\s*[:=]\s*[\'"]?([0-9a-fA-F\-]{36})[\'"]?',
    'Azure Client Secret': r'(?i)azure_client_secret\s*[:=]\s*[\'"]?([a-zA-Z0-9/+=]{32,})[\'"]?',
    
    # Firebase
    'Firebase API Key': r'(?i)firebase_api_key\s*:\s*[\'"]?([A-Za-z0-9_]{32})[\'"]?',
    'Firebase Database URL': r'https:\/\/[a-z0-9-]+\.firebaseio\.com',
    'Firebase Storage Bucket': r'(?i)"storageBucket"\s*:\s*"([A-Za-z0-9\-_]+\.appspot\.com)"',

    # Stripe
    'Stripe API Key': r'(?i)sk_live_[0-9a-zA-Z]{24}',
    'Stripe Publishable Key': r'(?i)pk_live_[0-9a-zA-Z]{24}',
    
    # PayPal
    'PayPal Client ID': r'(?i)paypal_client_id\s*:\s*[\'"]?([A-Za-z0-9-_]{15,})[\'"]?',
    'PayPal Secret': r'(?i)paypal_secret\s*:\s*[\'"]?([A-Za-z0-9-_]{15,})[\'"]?',

    # GitHub
    'GitHub Access Token': r'ghp_[A-Za-z0-9_]{36}',
    'GitHub OAuth Token': r'gho_[A-Za-z0-9_]{36}',
    'GitHub Secret Key': r'(?i)github_secret_key\s*:\s*[\'"]?([A-Za-z0-9_]{40})[\'"]?',

    # Slack
    'Slack Webhook URL': r'https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\/-]+',
    'Slack API Key': r'(?i)xox[baprs]-[A-Za-z0-9]{10,48}',

    # Twilio
    'Twilio Account SID': r'(?i)twilio_account_sid\s*:\s*[\'"]?([A-Za-z0-9]{34})[\'"]?',
    'Twilio Auth Token': r'(?i)twilio_auth_token\s*:\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    
    # Heroku
    'Heroku API Key': r'(?i)heroku_api_key\s*:\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    
    # Mailgun
    'Mailgun API Key': r'(?i)mailgun_api_key\s*:\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',

    # SendGrid
    'SendGrid API Key': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',

    # Dropbox
    'Dropbox API Key': r'dbx_[A-Za-z0-9]{64}',

    # DigitalOcean
    'DigitalOcean Token': r'[A-Za-z0-9]{64}',

    # Algolia
    'Algolia API Key': r'(?i)algolia_api_key\s*[:=]\s*[\'"]?([a-f0-9]{32})[\'"]?',
    'Algolia Admin Key': r'(?i)algolia_admin_key\s*[:=]\s*[\'"]?([a-f0-9]{32})[\'"]?',

    # Square
    'Square Access Token': r'sq0atp-[A-Za-z0-9\-_]{22,43}',
    
    # LinkedIn
    'LinkedIn Secret Key': r'(?i)linkedin_secret_key\s*[:=]\s*[\'"]?([A-Za-z0-9_]{32})[\'"]?',

    # Instagram
    'Instagram Access Token': r'(?i)instagram_access_token\s*:\s*[\'"]?([A-Za-z0-9\-._]+)[\'"]?',

    # Facebook
    'Facebook Access Token': r'(?i)EAACEdEose0cBA[0-9A-Za-z]+',
    'Facebook Secret Key': r'(?i)fb_secret_key\s*[:=]\s*[\'"]?([a-f0-9]{32})[\'"]?',

    # Microsoft
    'Microsoft Client ID': r'(?i)microsoft_client_id\s*[:=]\s*[\'"]?([0-9a-fA-F\-]{36})[\'"]?',
    'Microsoft Client Secret': r'(?i)microsoft_client_secret\s*[:=]\s*[\'"]?([A-Za-z0-9/_+=]{32,})[\'"]?',

    # Shopify
    'Shopify API Key': r'(?i)shopify_api_key\s*[:=]\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',
    'Shopify Access Token': r'(?i)shopify_access_token\s*[:=]\s*[\'"]?([A-Za-z0-9]{32})[\'"]?',

    # Cloudflare
    'Cloudflare API Key': r'(?i)cloudflare_api_key\s*[:=]\s*[\'"]?([A-Za-z0-9]{37})[\'"]?',

    # JWT Tokens
    'JWT Token': r'ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',

    # Basic Auth
    'Basic Auth Credentials': r'[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9_\-]+\.[a-zA-Z]{2,}',

    # Miscellaneous Secrets
    'Secret Key': r'(?i)secret_key\s*[:=]\s*[\'"]?([A-Za-z0-9/_+=\-]{32,})[\'"]?',
    'API Key': r'(?i)api_key\s*[:=]\s*[\'"]?([A-Za-z0-9/_+=\-]{32,})[\'"]?',
    'Private Key': r'(?i)"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----[A-Za-z0-9/+=\s]+-----END PRIVATE KEY-----"',
}

    found_secrets = {}
    for key, pattern in secret_patterns.items():
        matches = re.findall(pattern, js_content)
        if matches:
            unique_matches = list(set(matches))
            found_secrets[key] = unique_matches

    return found_secrets

def signal_handler(sig, frame):
    choice = input(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Do you want to close JSBOSS? (Y/N): ").strip().lower()
    if choice == 'y':
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Closing JSBOSS...")
        sys.exit(0)
    else:
        print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} Continuing execution...")

def auto_generate_output_file(domain_name):
    return f"output_{domain_name}.txt"

def get_domain_from_url(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

def main(input_file, look_for_secrets, look_for_urls):
    clear_screen()
    print_banner()

    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    with open(input_file, 'r') as file:
        js_links = file.readlines()

    extracted_links = []
    all_secrets = {}

    for js_link in js_links:
        js_link = js_link.strip()
        if not js_link:
            continue
        
        try:
            response = requests.get(js_link, verify=False)
            response.raise_for_status()

            domain_name = get_domain_from_url(js_link)
            output_file = auto_generate_output_file(domain_name)

            if look_for_urls:
                links = extract_links_from_js(response.text)
                extracted_links.extend(links)
                print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {Fore.YELLOW}Extracted {len(links)} links from {js_link}{Style.RESET_ALL}")

                for link in links:
                    print(f"{Fore.GREEN}[+] {link}{Style.RESET_ALL}")

            if look_for_secrets:
                secrets = extract_secrets(response.text)
                if secrets:
                    all_secrets[js_link] = secrets
                    print(f"{Fore.GREEN}[+] Secrets found in {js_link}: {json.dumps(secrets, indent=2)}{Style.RESET_ALL}")

        except requests.exceptions.SSLError as ssl_err:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} SSL error while fetching {js_link}: {str(ssl_err)}")
        except requests.RequestException as e:
            print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Failed to fetch {js_link}: {str(e)}")

    if extracted_links and look_for_urls:
        with open(output_file, 'w') as out_file:
            for link in extracted_links:
                out_file.write(link + '\n')
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {Fore.YELLOW}Links saved to {output_file}{Style.RESET_ALL}")

    if all_secrets and look_for_secrets:
        secrets_output_file = output_file.replace('.txt', '_secrets.json')
        with open(secrets_output_file, 'w') as secrets_file:
            json.dump(all_secrets, secrets_file, indent=2)
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {Fore.YELLOW}Secrets saved to {secrets_output_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTSTP, signal_handler)

    parser = argparse.ArgumentParser(description='Extract links and secrets from JavaScript files.')
    parser.add_argument('-f', '--file', help='File containing JavaScript links', required=True)
    parser.add_argument('--secrets', action='store_true', help='Look for secrets in JavaScript content')
    parser.add_argument('--urls', action='store_true', help='Extract URLs from JavaScript content')
    args = parser.parse_args()

    main(args.file, args.secrets, args.urls)
