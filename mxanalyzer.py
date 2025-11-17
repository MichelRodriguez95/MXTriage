import dns.resolver
import re, os, random
import sys
import argparse
import signal
import requests
import json
import time
import ipaddress
import base64

class Colors:
    if sys.stdout.isatty() and os.name != 'nt':
        RED = '\033[91m'
        ORANGE = '\033[33m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BOLD = '\033[1m'
        END = '\033[0m'
    elif sys.stdout.isatty() and os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            RED = '\033[91m'
            ORANGE = '\033[33m'
            BLUE = '\033[94m'
            GREEN = '\033[92m'
            YELLOW = '\033[93m'
            BOLD = '\033[1m'
            END = '\033[0m'
        except:
            RED = ORANGE = BLUE = GREEN = YELLOW = BOLD = END = ''
    else:
        RED = ORANGE = BLUE = GREEN = YELLOW = BOLD = END = ''


def signal_handler(sig, frame):
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def print_critical(text):
    print(f"{Colors.RED}{Colors.BOLD}{text}{Colors.END}")


def print_medium(text):
    print(f"{Colors.ORANGE}{Colors.BOLD}{text}{Colors.END}")


def print_low(text):
    print(f"{Colors.BLUE}{Colors.BOLD}{text}{Colors.END}")


def print_good(text):
    print(f"{Colors.GREEN}{Colors.BOLD}{text}{Colors.END}")


def print_info(text):
    print(f"{Colors.BLUE}{text}{Colors.END}")

def get_default_fingerprints():
    print_info("Using extended default fingerprints")
    return [
        {
            "service": "AWS S3",
            "cname": ["s3.amazonaws.com", "s3-website-us-east-1.amazonaws.com", "s3-website."],
            "fingerprint": "NoSuchBucket",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "GitHub Pages",
            "cname": ["github.io", "github.map.fastly.net"],
            "fingerprint": "There isn't a GitHub Pages site here",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Heroku",
            "cname": ["herokuapp.com", "herokussl.com"],
            "fingerprint": "No such app",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Shopify",
            "cname": ["myshopify.com"],
            "fingerprint": "Sorry, this shop is currently unavailable",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Fastly",
            "cname": ["fastly.net"],
            "fingerprint": "Fastly error: unknown domain",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Azure Blob Storage",
            "cname": ["blob.core.windows.net"],
            "fingerprint": "ResourceNotFound",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Google Cloud Storage",
            "cname": ["storage.googleapis.com", "c.storage.googleapis.com"],
            "fingerprint": "NoSuchBucket",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Bitbucket",
            "cname": ["bitbucket.io"],
            "fingerprint": "Repository not found",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "AWS CloudFront",
            "cname": [".cloudfront.net"],
            "fingerprint": "ERROR: The request could not be satisfied",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "AWS Elastic Beanstalk",
            "cname": [".elasticbeanstalk.com"],
            "fingerprint": "404 Not Found",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Readme.io",
            "cname": ["readme.io"],
            "fingerprint": "Project doesnt exist... yet!",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Ghost.io",
            "cname": ["ghost.io"],
            "fingerprint": "The thing you were looking for is no longer here",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Pantheon",
            "cname": ["pantheonsite.io"],
            "fingerprint": "The gods are wise",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Zendesk",
            "cname": ["zendesk.com"],
            "fingerprint": "Help Center Closed",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Unbounce",
            "cname": ["unbounce.com"],
            "fingerprint": "The requested URL was not found on this server",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Intercom",
            "cname": ["custom.intercom.help"],
            "fingerprint": "This page is reserved for magical things",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Worksites",
            "cname": ["worksites.net"],
            "fingerprint": "Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Agile CRM",
            "cname": ["agilecrm.com"],
            "fingerprint": "Sorry, this page is no longer available.",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Aftership",
            "cname": ["aftership.com"],
            "fingerprint": "Oops.</h2><p class=\"text-muted text-tight\">The page you're looking for doesn't exist.",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Aha",
            "cname": ["aha.io"],
            "fingerprint": "There is no portal here ... sending you back to Aha!",
            "status": "vulnerable",
            "vulnerable": True
        }
    ]


def download_fingerprints_from_github():

    urls = [
        "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json",
        "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/gh-pages/fingerprints.json",
        "https://cdn.jsdelivr.net/gh/EdOverflow/can-i-take-over-xyz@master/fingerprints.json"
    ]

    for url in urls:
        try:
            print_info(f"Trying to download fingerprints from: {url}")
            print()
            response = requests.get(url, timeout=15)
            response.raise_for_status()

            fingerprints = response.json()
            if fingerprints and len(fingerprints) > 0:
                print_good(f"Successfully downloaded {len(fingerprints)} fingerprints from {url}")
                return fingerprints
            else:
                print(f"{Colors.ORANGE}Empty response from {url}{Colors.END}")

        except requests.exceptions.RequestException as e:
            print(f"{Colors.ORANGE}Failed to download from {url}: {e}{Colors.END}")
            continue
        except json.JSONDecodeError as e:
            print(f"{Colors.ORANGE}Invalid JSON from {url}: {e}{Colors.END}")
            continue
        except Exception as e:
            print(f"{Colors.ORANGE}Unexpected error from {url}: {e}{Colors.END}")
            continue

    print(f"{Colors.RED}All download attempts failed, using default fingerprints{Colors.END}")
    return get_default_fingerprints()


def load_takeover_fingerprints(json_file_path="fingerprints.json"):

    try:
        if os.path.exists(json_file_path):
            print_info(f"Loading takeover fingerprints from: {json_file_path}")
            with open(json_file_path, 'r', encoding='utf-8') as f:
                fingerprints = json.load(f)
                if fingerprints:
                    print_good(f"Loaded {len(fingerprints)} takeover fingerprints from local file")
                    return fingerprints

        print_info("Local fingerprints not found, downloading from GitHub...")
        fingerprints = download_fingerprints_from_github()

        if fingerprints:
            try:
                with open(json_file_path, 'w', encoding='utf-8') as f:
                    json.dump(fingerprints, f, indent=2, ensure_ascii=False)
                print_good(f"Downloaded and saved {len(fingerprints)} fingerprints to {json_file_path}")
            except Exception as e:
                print(f"{Colors.RED}Warning: Could not save fingerprints to file: {e}{Colors.END}")

        return fingerprints

    except Exception as e:
        print(f"{Colors.RED}Error loading takeover fingerprints: {e}{Colors.END}")
        print(f"{Colors.ORANGE}Falling back to default fingerprints{Colors.END}")
        return get_default_fingerprints()

def check_http_fingerprint(domain, fingerprint):
    result = {
        'vulnerable': False,
        'response_snippet': None
    }

    schemes = ['https', 'http']

    for scheme in schemes:
        try:
            url = f"{scheme}://{domain}"
            response = requests.get(
                url,
                timeout=15,
                verify=False,
                allow_redirects=True,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
            )

            if fingerprint in response.text:
                result['vulnerable'] = True
                result['response_snippet'] = response.text[:200] + "..." if len(response.text) > 200 else response.text
                break

        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.RequestException:
            continue
        except Exception:
            continue

    return result


def check_subdomain_takeover(domain, fingerprints=None):
    if fingerprints is None:
        fingerprints = load_takeover_fingerprints()
        if not fingerprints:
            print(f"{Colors.RED}Error: No fingerprints available for takeover detection{Colors.END}")
            return {
                'domain': domain,
                'vulnerable': False,
                'error_message': 'No fingerprints available'
            }

    result = {
        'domain': domain,
        'vulnerable': False,
        'service': None,
        'fingerprint': None,
        'response_body': None,
        'cname_record': None,
        'error_message': None,
        'status': 'safe'
    }

    try:
        try:
            cname_answer = dns.resolver.resolve(domain, 'CNAME')
            cname = str(cname_answer[0].target).rstrip('.')
            result['cname_record'] = cname
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            result['error_message'] = "No CNAME record found"
            return result
        except Exception as e:
            result['error_message'] = f"CNAME lookup error: {e}"
            return result

        for fp in fingerprints:
            if not fp.get('cname'):
                continue

            for cname_pattern in fp['cname']:
                if cname_pattern and cname_pattern in cname:
                    if fp.get('vulnerable', False):
                        if fp.get('fingerprint') and fp['fingerprint'].strip():
                            http_result = check_http_fingerprint(domain, fp['fingerprint'])
                            if http_result['vulnerable']:
                                result.update({
                                    'vulnerable': True,
                                    'service': fp.get('service'),
                                    'fingerprint': fp.get('fingerprint'),
                                    'response_body': http_result['response_snippet'],
                                    'status': fp.get('status', 'vulnerable')
                                })
                                return result
                        else:
                            result.update({
                                'vulnerable': True,
                                'service': fp.get('service'),
                                'status': fp.get('status', 'vulnerable'),
                                'fingerprint': 'CNAME-based detection'
                            })
                            return result

        result['error_message'] = "No vulnerable service detected"

    except Exception as e:
        result['error_message'] = f"Unexpected error: {e}"

    return result


def subdomain_takeover_scan(domain, subdomains=None):
    if subdomains is None:
        subdomains = discover_subdomains(domain)

    if not subdomains:
        return []

    print_info(f"Loading takeover fingerprints for {len(subdomains)} subdomains...")
    fingerprints = load_takeover_fingerprints()
    print_good(f"Using {len(fingerprints)} fingerprints for takeover detection")
    print()

    takeover_vulnerabilities = []

    total = len(subdomains)
    bar_length = 30

    for i, subdomain in enumerate(subdomains):
        result = check_subdomain_takeover(subdomain, fingerprints)
        if result['vulnerable']:
            takeover_vulnerabilities.append(result)

        progress = (i + 1) / total
        filled_length = int(bar_length * progress)
        bar = '█' * filled_length + ' ' * (bar_length - filled_length)
        percent = int(100 * progress)

        print(f"\r{Colors.GREEN}[{bar}]{Colors.END} {percent}% ({i + 1}/{total})", end='', flush=True)

    print("\n")

    return takeover_vulnerabilities


def discover_subdomains(domain):
    common_subdomains = [
        'www', 'mail', 'email', 'smtp', 'mx', 'mx1', 'mx2', 'mx3',
        'newsletter', 'marketing', 'campaign', 'bulk', 'transactional',
        'notifications', 'alerts', 'noreply', 'contact', 'info',
        'support', 'help', 'service', 'admin', 'administrator',
        'api', 'app', 'apps', 'backend', 'frontend', 'cdn',
        'static', 'assets', 'media', 'uploads', 'files',
        'blog', 'news', 'forum', 'community', 'shop', 'store',
        'payment', 'billing', 'invoice', 'account', 'accounts',
        'secure', 'portal', 'dashboard', 'panel', 'control',
        'test', 'dev', 'development', 'staging', 'stage', 'prod',
        'web', 'webmail', 'ftp', 'ssh', 'vpn', 'remote',
        'office', 'share', 'sharepoint', 'collab', 'collaboration',
        'docs', 'documents', 'wiki', 'knowledgebase', 'helpdesk',
        'status', 'monitor', 'monitoring', 'log', 'logs',
        'db', 'database', 'sql', 'nosql', 'redis', 'cache',
        'search', 'query', 'analytics', 'stats', 'statistics',
        'img', 'images', 'photo', 'photos', 'video', 'videos',
        'music', 'audio', 'podcast', 'stream', 'streaming',
        'mobile', 'm', 'wap', 'android', 'ios', 'iphone',
        'demo', 'example', 'sample', 'temp', 'tmp',
        'old', 'archive', 'backup', 'mirror', 'copy',
        'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'dns',
        'router', 'switch', 'firewall', 'gateway', 'proxy',
        'cpanel', 'plesk', 'whm', 'directadmin', 'webmin',
        'autodiscover', 'autoconfig', 'msoid', 'lync', 'skype',
        'teams', 'meet', 'conference', 'webinar', 'zoom',
        'git', 'svn', 'repo', 'repository', 'code',
        'jenkins', 'ci', 'cd', 'deploy', 'pipeline',
        'docker', 'kubernetes', 'k8s', 'container', 'vm',
        'aws', 'azure', 'gcp', 'cloud', 'digitalocean',
        'vps', 'server', 'servers', 'host', 'hosting'
    ]

    discovered = []
    for sub in common_subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            dns.resolver.resolve(subdomain, 'A')
            discovered.append(subdomain)
        except:
            try:
                dns.resolver.resolve(subdomain, 'CNAME')
                discovered.append(subdomain)
            except:
                pass
    return discovered


def setup_dns_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    return resolver


def get_spf_record(domain):
    try:
        resolver = setup_dns_resolver()
        answers = resolver.resolve(domain, 'TXT')
        for rdata in answers:
            record = ''.join([str(txt) for txt in rdata.strings])
            if 'v=spf1' in record:
                return record
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    except dns.resolver.Timeout:
        return 'TIMEOUT'
    except Exception:
        return None
    return None


def is_ip_overlap(ip1, ip2):

    try:
        network1 = ipaddress.ip_network(ip1, strict=False)
        network2 = ipaddress.ip_network(ip2, strict=False)
        return network1.overlaps(network2)
    except ValueError:
        return False


def check_spf_recursive(domain, max_depth=10, current_depth=0, visited=None):

    if visited is None:
        visited = set()

    if current_depth > max_depth:
        return {
            'lookup_count': 0,
            'error': f"Max recursion depth exceeded ({max_depth})"
        }

    if domain in visited:
        return {
            'lookup_count': 0,
            'error': f"Circular reference detected for domain {domain}"
        }

    visited.add(domain)

    result = {
        'lookup_count': 1,
        'includes': [],
        'errors': []
    }

    try:
        resolver = setup_dns_resolver()
        spf_records = resolver.resolve(domain, 'TXT')
        spf_record = None

        for rdata in spf_records:
            record = ''.join([str(txt) for txt in rdata.strings])
            if "v=spf1" in record:
                spf_record = record
                break

        if not spf_record:
            result['errors'].append(f"No SPF record found for {domain}")
            return result

        parts = spf_record.split()

        for part in parts:
            if part.startswith("include:"):
                included_domain = part[8:]
                result['includes'].append(included_domain)

                included_result = check_spf_recursive(
                    included_domain,
                    max_depth,
                    current_depth + 1,
                    visited.copy()
                )

                result['lookup_count'] += included_result.get('lookup_count', 0)

                if 'error' in included_result:
                    result['errors'].append(included_result['error'])

                if 'errors' in included_result:
                    result['errors'].extend(included_result['errors'])

            elif part.startswith("redirect="):
                redirect_domain = part[9:]

                redirect_result = check_spf_recursive(
                    redirect_domain,
                    max_depth,
                    current_depth + 1,
                    visited.copy()
                )

                result['lookup_count'] += redirect_result.get('lookup_count', 0)

                if 'error' in redirect_result:
                    result['errors'].append(redirect_result['error'])

                if 'errors' in redirect_result:
                    result['errors'].extend(redirect_result['errors'])

            elif part.startswith("a:") or part == "a":
                result['lookup_count'] += 1

            elif part.startswith("mx:") or part == "mx":
                result['lookup_count'] += 1

            elif part.startswith("ptr:") or part == "ptr":
                result['lookup_count'] += 1

    except Exception as e:
        result['errors'].append(f"Error checking SPF for {domain}: {str(e)}")

    return result


def check_spf_unregistered_domains(spf_record, domain, max_depth=5, current_depth=0, visited=None):

    if visited is None:
        visited = set()

    if current_depth > max_depth or domain in visited:
        return []

    visited.add(domain)
    vulnerabilities = []
    unregistered_domains = []

    includes = re.findall(r'include:([^\s]+)', spf_record)
    redirects = re.findall(r'redirect=([^\s]+)', spf_record)

    all_domains = includes + redirects

    for test_domain in all_domains:
        try:
            dns.resolver.resolve(test_domain, 'A')

            try:
                test_spf = get_spf_record(test_domain)
                if test_spf and test_spf != 'TIMEOUT':
                    recursive_vulns = check_spf_unregistered_domains(
                        test_spf, test_domain, max_depth, current_depth + 1, visited.copy()
                    )
                    vulnerabilities.extend(recursive_vulns)
            except Exception:
                pass

        except dns.resolver.NXDOMAIN:
            unregistered_domains.append(test_domain)
        except (dns.resolver.NoAnswer, dns.resolver.Timeout):
            continue
        except Exception:
            continue

    if unregistered_domains:
        vulnerabilities.append({
            'type': 'SPF_UNREGISTERED_DOMAINS',
            'severity': 'CRITICAL',
            'description': f'Unregistered domains in SPF chain: {", ".join(unregistered_domains)}',
            'solution': 'Remove unregistered domains from SPF or register them',
            'attack_methods': [
                'Attacker can register the domain and configure malicious SPF',
                'Complete SPF bypass by controlling included domains',
                'Legitimate email spoofing through domain registration',
                'Permanent backdoor into email authentication'
            ]
        })

    return vulnerabilities


def check_dkim_alignment(domain):

    alignment_info = {
        'domain': domain,
        'mx_records': [],
        'alignment_issues': [],
        'recommendations': []
    }

    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')

        for rdata in mx_answers:
            mx_domain = str(rdata.exchange).rstrip('.')
            alignment_info['mx_records'].append(mx_domain)

            if not mx_domain.endswith(domain):
                alignment_info['alignment_issues'].append(
                    f"Mail server {mx_domain} is not aligned with {domain}"
                )

                try:
                    mx_base_domain = '.'.join(mx_domain.split('.')[-2:])
                    dkim_selectors = dselectors()[:500]

                    dkim_found = False
                    for selector in dkim_selectors:
                        dkim_record = f"{selector}._domainkey.{mx_base_domain}"
                        try:
                            dns.resolver.resolve(dkim_record, 'TXT')
                            dkim_found = True
                            break
                        except:
                            continue

                    if not dkim_found:
                        alignment_info['recommendations'].append(
                            f"Configure DKIM for mail server {mx_domain}"
                        )
                except Exception:
                    alignment_info['recommendations'].append(
                        f"Verify DKIM configuration for mail server {mx_domain}"
                    )

    except Exception as e:
        alignment_info['alignment_issues'].append(f"Error checking MX records: {str(e)}")

    return alignment_info


def estimate_key_size(key_length):

    if key_length < 100:
        return 512
    elif key_length < 200:
        return 1024
    elif key_length < 400:
        return 2048
    else:
        return 4096


def analyze_dkim_record_detailed(selector, record_data, domain):

    dkim_details = {
        'selector': selector,
        'domain': domain,
        'version': None,
        'key_type': None,
        'key_size': None,
        'hash_algorithms': [],
        'testing_mode': False,
        'services': [],
        'flags': [],
        'security_level': 'None',
        'issues': [],
        'recommendations': []
    }

    record_lower = record_data.lower()

    fields = {}
    for field in record_data.split(';'):
        field = field.strip()
        if '=' in field:
            key, value = field.split('=', 1)
            fields[key.strip()] = value.strip()

    if 'v' in fields:
        dkim_details['version'] = fields['v']
        if fields['v'] != 'DKIM1':
            dkim_details['issues'].append(f"Non-standard DKIM version: {fields['v']}")
            dkim_details['recommendations'].append("Use standard DKIM version (DKIM1)")

    if 'k' in fields:
        dkim_details['key_type'] = fields['k']
        if fields['k'] not in ['rsa', 'ed25519']:
            dkim_details['issues'].append(f"Non-standard key type: {fields['k']}")
            dkim_details['recommendations'].append("Use standard key types (rsa or ed25519)")
    else:
        dkim_details['key_type'] = 'rsa'

    if 'p' in fields and fields['p']:
        key_length = len(fields['p'])
        estimated_size = estimate_key_size(key_length)
        dkim_details['key_size'] = estimated_size

        if estimated_size < 1024:
            dkim_details['issues'].append(f"Weak key size (estimated {estimated_size} bits)")
            dkim_details['recommendations'].append("Use at least 2048-bit RSA keys")
            dkim_details['security_level'] = 'Low'
        elif estimated_size < 2048:
            dkim_details['issues'].append(f"Moderate key size (estimated {estimated_size} bits)")
            dkim_details['recommendations'].append("Consider upgrading to 2048-bit or higher")
            dkim_details['security_level'] = 'Medium'
        else:
            dkim_details['security_level'] = 'High'

    if 'h' in fields:
        algorithms = fields['h'].split(':')
        dkim_details['hash_algorithms'] = algorithms

        if 'sha1' in algorithms and 'sha256' not in algorithms:
            dkim_details['issues'].append("Uses weak SHA-1 algorithm without SHA-256")
            dkim_details['recommendations'].append("Use SHA-256 hash algorithm")
            if dkim_details['security_level'] == 'High':
                dkim_details['security_level'] = 'Medium'

    if 't' in fields and 'y' in fields['t']:
        dkim_details['testing_mode'] = True
        dkim_details['issues'].append("DKIM in testing mode")
        dkim_details['recommendations'].append("Disable testing mode for production")
        dkim_details['security_level'] = 'Low'

    if 's' in fields:
        services = fields['s'].split(':')
        dkim_details['services'] = services

        if '*' in services:
            dkim_details['flags'].append("All services allowed")
        elif 'email' not in services:
            dkim_details['issues'].append("May not be configured for email service")
            dkim_details['recommendations'].append("Add email service to allowed services")

    return dkim_details

def check_spf_recursion_loops(spf_record, domain, visited=None):
    vulnerabilities = []
    if visited is None:
        visited = set()

    if domain in visited:
        return [{
            'type': 'SPF_RECURSION_LOOP',
            'severity': 'MEDIUM',
            'description': f'SPF infinite lookup loop detected involving {domain}',
            'solution': 'Fix SPF include/redirect chains to remove circular references',
            'attack_methods': [
                'SPF PermError during validation',
                'Some email receivers may accept emails despite the error',
                'Inconsistent email authentication behavior'
            ]
        }]

    visited.add(domain)

    includes = re.findall(r'include:([^\s]+)', spf_record)
    redirects = re.findall(r'redirect=([^\s]+)', spf_record)

    for include_domain in includes:
        include_spf = get_spf_record(include_domain)
        if include_spf and include_spf != 'TIMEOUT':
            loop_vulns = check_spf_recursion_loops(include_spf, include_domain, visited.copy())
            vulnerabilities.extend(loop_vulns)

    for redirect_domain in redirects:
        redirect_spf = get_spf_record(redirect_domain)
        if redirect_spf and redirect_spf != 'TIMEOUT':
            loop_vulns = check_spf_recursion_loops(redirect_spf, redirect_domain, visited.copy())
            vulnerabilities.extend(loop_vulns)

    return vulnerabilities


def dselectors():
    all_selectors = [
        'google', 'gmail', 'gsuite', 'workspace',
        'selector1', 'selector2', 'selector3', 'outlook', 'microsoft', 'office365', 'exchange',
        'k1', 'k2', 'k3', 'ses', 'amazon', 'aws', 'k4', 'k5', 'k6', 'k7', 'k8', 'k9', 'k0', 'k10',
        's1', 's2', 's3', 'sendgrid', 'sg', 's4', 's5', 's6', 's7', 's8', 's9', 's0', 's10',
        'mandrill', 'mailchimp', 'mc', 'chimp',
        'mg', 'mailgun', 'email',
        'pm', 'postmark', 'pmk1',
        'sparkpost', 'sp', 'spk1',
        'zoho', 'zmail', 'zm',
        'yahoo', 'ymail', 'aol',
        'apple', 'icloud', 'mac', 'google', 'googlemail', 'googleapi', 'gapi', 'googleapis', 'gapis',
        'protonmail', 'proton', 'mxvault', 'mxv',
        'fastmail', 'fm',
        'hubspot', 'hs',
        'activecampaign', 'ac',
        'getresponse', 'gr',
        'constantcontact', 'cc',
        'campaignmonitor', 'cm',
        'sendinblue', 'brevo', 'sib',
        'mailjet', 'mj',
        'sendpulse', 'spulse',
        'elasticemail', 'ee',
        'default', 'dkim', 'domainkey', 'key', 'selector',
        '1', '2', '3', '4', '5', '6', '7', '8', '9', '10',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'dk', 'dk1', 'dk2', 'dk3', 'key1', 'key2', 'key3',
        'sig', 'sig1', 'sign', 'signature',
        'jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec',
        '2023', '2024', '2025', '2022', '2021', '2025',
        'spring', 'summer', 'fall', 'winter',
        'mail', 'smtp', 'mx', 'mx1', 'mx2', 'mx3',
        'server', 'srv', 'srv1', 'srv2',
        'newsletter', 'marketing', 'transactional', 'bulk', 'mass', 'broadcast', 'campaign',
        'prod', 'production', 'live', 'dev', 'development', 'staging', 'test', 'qa',
        'stage', 'preprod', 'sandbox',
        'us', 'usa', 'eu', 'europe', 'asia', 'global', 'world', 'na', 'sa', 'au', 'uk', 'de', 'fr', 'jp',
        'sel1', 'sel2', 'sel3', 'sel4', 'sel5',
        'sig1', 'sig2', 'sig3', 'key1', 'key2', 'key3', 'dk1', 'dk2', 'dk3', 'mx1', 'mx2', 'mx3',
        'prod_mail', 'dev_mail', 'staging_mail', 'prod_smtp', 'dev_smtp',
        'live_marketing', 'test_transactional', 'us_mail', 'eu_mail', 'asia_mail',
        'us_marketing', 'eu_transactional', '2024_jan', '2024_feb', '2023_dec',
        '2024q1', '2024q2', '2024q3', '2024q4',
        'cpanel', 'plesk', 'whm', 'directadmin', 'panel',
        'godaddy', 'bluehost', 'siteground', 'hostgator', 'dreamhost',
        'cloudflare', 'cloud', 'cf', 'facebook', 'fb', 'twitter', 'tw',
        'instagram', 'ig', 'linkedin', 'li', 'shopify', 'woocommerce',
        'magento', 'bigcommerce', 'prestashop', 'wordpress', 'wp',
        'drupal', 'joomla', 'wix', 'squarespace',
    ]
    return sorted(list(set(all_selectors)))


def detect_protections(domain):
    protections = []
    protection_indicators = {
        'Proofpoint': {
            'mx_patterns': ['.pphosted.com', '.protection.outlook.com', '.pps.filterd.com'],
            'spf_patterns': ['include:spf.protection.outlook.com', 'include:_spf.ppe-hosted.com'],
            'description': 'Proofpoint Email Protection - Advanced threat protection',
            'bypass_difficulty': 'HIGH'
        },
        'Mimecast': {
            'mx_patterns': ['.mimecast.com', '.mimecast-mail.com', '.mcs.mimecast.com'],
            'spf_patterns': ['include:_netblocks.mimecast.com', 'include:_spf.mimecast.com'],
            'description': 'Mimecast Email Security - Cloud email security',
            'bypass_difficulty': 'HIGH'
        },
        'Microsoft Defender': {
            'mx_patterns': ['.protection.outlook.com', '.mail.protection.outlook.com'],
            'spf_patterns': ['include:spf.protection.outlook.com'],
            'description': 'Microsoft Defender for Office 365',
            'bypass_difficulty': 'HIGH'
        },
        'Cisco IronPort': {
            'mx_patterns': ['.ironport.com', '.cisco.com', '.cesmail.net'],
            'spf_patterns': ['include:_spf.cesmail.net', 'include:ironport.com'],
            'description': 'Cisco Email Security (IronPort)',
            'bypass_difficulty': 'MEDIUM'
        },
        'FireEye': {
            'mx_patterns': ['.fireeye.com', '.feye.com', '.mandiant.com'],
            'spf_patterns': ['include:_spf.fireeye.com'],
            'description': 'FireEye Email Security (now Trellix)',
            'bypass_difficulty': 'HIGH'
        },
        'FortiMail': {
            'mx_patterns': ['.fortimail.com', '.fortinet.com'],
            'spf_patterns': ['include:_spf.fortimail.com'],
            'description': 'Fortinet FortiMail',
            'bypass_difficulty': 'MEDIUM'
        },
        'Barracuda': {
            'mx_patterns': ['.barracudanetworks.com', '.barracuda.com'],
            'spf_patterns': ['include:_spf.barracudanetworks.com'],
            'description': 'Barracuda Email Security',
            'bypass_difficulty': 'MEDIUM'
        },
        'Sophos': {
            'mx_patterns': ['.sophos.com', '.sophos.news', '.sophoslab.net'],
            'spf_patterns': ['include:_spf.sophos.com'],
            'description': 'Sophos Email Security',
            'bypass_difficulty': 'MEDIUM'
        },
        'Trend Micro': {
            'mx_patterns': ['.trendmicro.com', '.tmcloud.com'],
            'spf_patterns': ['include:_spf.trendmicro.com'],
            'description': 'Trend Micro Email Security',
            'bypass_difficulty': 'MEDIUM'
        },
        'Symantec': {
            'mx_patterns': ['.symantec.com', '.messagelabs.com', '.symcb.com'],
            'spf_patterns': ['include:_spf.symantec.com', 'include:spf.messagelabs.com'],
            'description': 'Symantec Email Security (now Broadcom)',
            'bypass_difficulty': 'MEDIUM'
        },
        'McAfee': {
            'mx_patterns': ['.mcafee.com', '.mxcloud.com', '.mximail.com'],
            'spf_patterns': ['include:_spf.mcafee.com', 'include:spf.mxcloud.com'],
            'description': 'McAfee Email Security',
            'bypass_difficulty': 'MEDIUM'
        },
        'Forcepoint': {
            'mx_patterns': ['.forcepoint.com', '.websense.com', '.tfrcmm.com'],
            'spf_patterns': ['include:_spf.forcepoint.com', 'include:spf.websense.com'],
            'description': 'Forcepoint Email Security',
            'bypass_difficulty': 'MEDIUM'
        }
    }

    try:
        try:
            mx_answers = dns.resolver.resolve(domain, 'MX')
            for rdata in mx_answers:
                mx_server = str(rdata.exchange).rstrip('.').lower()

                for service_name, indicators in protection_indicators.items():
                    for pattern in indicators['mx_patterns']:
                        if pattern.lower() in mx_server:
                            protections.append({
                                'service': service_name,
                                'type': 'MX_RECORD',
                                'server': mx_server,
                                'description': indicators['description'],
                                'bypass_difficulty': indicators['bypass_difficulty'],
                                'detection_method': f'MX record matches {pattern}'
                            })
        except:
            pass

        try:
            txt_answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in txt_answers:
                record = ''.join([str(txt) for txt in rdata.strings]).lower()
                if 'v=spf1' in record:

                    for service_name, indicators in protection_indicators.items():
                        for pattern in indicators['spf_patterns']:
                            if pattern.lower() in record:
                                protections.append({
                                    'service': service_name,
                                    'type': 'SPF_INCLUDE',
                                    'record': record[:100] + '...' if len(record) > 100 else record,
                                    'description': indicators['description'],
                                    'bypass_difficulty': indicators['bypass_difficulty'],
                                    'detection_method': f'SPF includes {pattern}'
                                })
        except:
            pass

    except Exception as e:
        pass

    return protections


def get_nameservers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(ns.target).rstrip('.') for ns in answers]
        return nameservers
    except Exception:
        return []


def get_mx_servers(domain):
    vulnerabilities = []
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_servers = []
        for rdata in answers:
            server = str(rdata.exchange).rstrip('.')
            priority = rdata.preference
            try:
                ip_answers = dns.resolver.resolve(server, 'A')
                ips = [str(ip) for ip in ip_answers]
            except:
                ips = ["Could not resolve IP"]
            mx_servers.append({
                'server': server,
                'priority': priority,
                'ips': ips
            })
        mx_servers.sort(key=lambda x: x['priority'])
        print()
        print_low(f"Found {len(mx_servers)} MX servers:")
        print()
        for i, mx in enumerate(mx_servers, 1):
            print(f"  {i}. {mx['server']} (Priority: {mx['priority']})")
            for ip in mx['ips']:
                print(f"     IP: {ip}")
        print()

        if len(mx_servers) == 1:
            vulnerabilities.append({
                'type': 'SINGLE_MX_SERVER',
                'severity': 'HIGH',
                'description': 'Only one MX server - single point of failure',
                'solution': 'Add backup MX servers with lower priority',
                'attack_methods': [
                    'Targeted DDoS against single mail server',
                    'Single server compromise affects all email',
                    'No failare you for email delivery'
                ]
            })

        vulnerable_servers = ['exchange', 'cpanel', 'plesk', 'zimbra']
        for mx in mx_servers:
            server_lower = mx['server'].lower()
            for vuln_server in vulnerable_servers:
                if vuln_server in server_lower:
                    vuln = {
                        'type': 'POTENTIALLY_VULNERABLE_MAIL_SERVER',
                        'severity': 'MEDIUM',
                        'description': f'MX server {mx["server"]} may run known vulnerable software',
                        'solution': 'Ensure mail server software is updated and patched',
                        'attack_methods': [
                            'Exploit known vulnerabilities in mail server software',
                            'Targeted attacks against specific mail server types',
                            'Privilege escalation on vulnerable mail servers'
                        ]
                    }
                    vulnerabilities.append(vuln)

        return mx_servers, vulnerabilities

    except dns.resolver.NoAnswer:
        vuln = {
            'type': 'NO_MX_RECORDS',
            'severity': 'CRITICAL',
            'description': 'Domain has no MX records',
            'solution': 'Configure MX records for email delivery',
            'attack_methods': [
                'Complete email delivery failure',
                'Business communication disruption',
                'Cannot receive legitimate emails'
            ]
        }
        vulnerabilities.append(vuln)
        print_critical("No MX records found")
        print()
        return [], vulnerabilities
    except Exception as e:
        print(f"Error resolving MX records: {e}")
        return [], vulnerabilities


def spf_scan(domain):
    vulnerabilities = []
    all_txt_records = []

    try:
        resolver = setup_dns_resolver()
        answers = resolver.resolve(domain, 'TXT')
        spf_record = None
        for rdata in answers:
            record = ''.join([str(txt) for txt in rdata.strings])
            all_txt_records.append(record)
            if 'v=spf1' in record:
                spf_record = record
                break

        if spf_record:
            print("SPF Record Found:")
            print()
            print_low(f"SPF Record: {spf_record}")
            print()

        if spf_record:
            unregistered_vulns = check_spf_unregistered_domains(spf_record, domain)
            vulnerabilities.extend(unregistered_vulns)

        if spf_record:
            recursive_result = check_spf_recursive(domain)

            if recursive_result.get('error'):
                vulnerabilities.append({
                    'type': 'SPF_RECURSION_ERROR',
                    'severity': 'HIGH',
                    'description': f'SPF recursion error: {recursive_result["error"]}',
                    'solution': 'Fix SPF include/redirect chains to remove circular references',
                    'attack_methods': [
                        'SPF PermError during validation',
                        'Email delivery failures',
                        'Inconsistent email authentication'
                    ]
                })

            lookup_count = recursive_result.get('lookup_count', 0)
            if lookup_count > 10:
                vulnerabilities.append({
                    'type': 'SPF_DNS_LOOKUP_LIMIT_EXCEEDED',
                    'severity': 'CRITICAL',
                    'description': f'SPF exceeds DNS lookup limit ({lookup_count} > 10)',
                    'solution': 'Reduce number of DNS lookups in SPF record',
                    'attack_methods': [
                        'SPF validation failures',
                        'Email rejection due to PermError',
                        'DoS through DNS lookup exhaustion'
                    ]
                })

            ip4_ranges = re.findall(r'ip4:([\d./]+)', spf_record)
            for i, ip1 in enumerate(ip4_ranges):
                for j, ip2 in enumerate(ip4_ranges):
                    if i < j and is_ip_overlap(ip1, ip2):
                        vulnerabilities.append({
                            'type': 'SPF_IP_RANGE_OVERLAP',
                            'severity': 'LOW',
                            'description': f'Overlapping IP ranges in SPF: {ip1} and {ip2}',
                            'solution': 'Consolidate overlapping IP ranges',
                            'attack_methods': [
                                'Redundant SPF mechanisms',
                                'Inefficient SPF evaluation',
                                'Potential configuration confusion'
                            ]
                        })

        test_subdomains = [
            f"test-{random.randint(100000, 999999)}.{domain}",
            f"spf-check-{random.randint(100000, 999999)}.{domain}"
        ]

        wildcard_txt_found = False
        for test_sub in test_subdomains:
            try:
                txt_answers = resolver.resolve(test_sub, 'TXT')
                wildcard_txt_found = True
                has_wildcard_spf = False
                for rdata in txt_answers:
                    record = ''.join([str(txt) for txt in rdata.strings])
                    if 'v=spf1' in record:
                        has_wildcard_spf = True
                        break

                if not has_wildcard_spf:
                    vulnerabilities.append({
                        'type': 'WILDCARD_TXT_WITHOUT_SPF',
                        'severity': 'MEDIUM',
                        'description': 'Wildcard TXT records exist but no wildcard SPF policy',
                        'solution': 'Add SPF to wildcard TXT or implement specific subdomain SPF records',
                        'attack_methods': [
                            'Subdomains may send emails without SPF protection',
                            'Wildcard DNS without email authentication',
                            'Potential for subdomain email spoofing'
                        ]
                    })
                break

            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                continue
            except dns.resolver.Timeout:
                vulnerabilities.append({
                    'type': 'DNS_TIMEOUT',
                    'severity': 'LOW',
                    'description': f'DNS timeout when checking wildcard TXT for {domain}',
                    'solution': 'Check DNS configuration and network connectivity',
                    'attack_methods': [
                        'Incomplete SPF subdomain analysis',
                        'Potential missed vulnerabilities',
                        'Inconsistent scan results'
                    ]
                })
                break
            except Exception:
                continue

        email_related_subdomains = [
            'mail', 'email', 'smtp', 'mx', 'mx1', 'mx2', 'mx3',
            'newsletter', 'marketing', 'campaign', 'bulk', 'transactional',
            'notifications', 'alerts', 'noreply', 'contact', 'info',
            'support', 'help', 'service', 'admin', 'administrator'
        ]

        email_subs_without_spf = []
        for sub in email_related_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                try:
                    resolver.resolve(subdomain, 'A')
                    exists = True
                except:
                    try:
                        resolver.resolve(subdomain, 'MX')
                        exists = True
                    except:
                        exists = False

                if exists:
                    try:
                        txt_answers = resolver.resolve(subdomain, 'TXT')
                        has_spf = False
                        for rdata in txt_answers:
                            record = ''.join([str(txt) for txt in rdata.strings])
                            if 'v=spf1' in record:
                                has_spf = True
                                break
                        if not has_spf:
                            email_subs_without_spf.append(subdomain)
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        email_subs_without_spf.append(subdomain)
                    except dns.resolver.Timeout:
                        vulnerabilities.append({
                            'type': 'DNS_TIMEOUT',
                            'severity': 'LOW',
                            'description': f'DNS timeout when checking SPF for subdomain {subdomain}',
                            'solution': 'Check DNS configuration and retry',
                            'attack_methods': [
                                'Incomplete subdomain SPF analysis',
                                'Potential missed subdomain vulnerabilities'
                            ]
                        })

            except Exception:
                continue

        if email_subs_without_spf and not wildcard_txt_found:
            vulnerabilities.append({
                'type': 'EMAIL_SUBDOMAINS_WITHOUT_SPF',
                'severity': 'HIGH',
                'description': f'Email-related subdomains without SPF: {", ".join(email_subs_without_spf[:5])}',
                'solution': 'Implement SPF records for all subdomains that send emails',
                'attack_methods': [
                    'Direct email spoofing from email-related subdomains',
                    'Phishing attacks using legitimate-looking subdomains',
                    'No authentication for subdomain email services'
                ]
            })

        if not spf_record:
            vulnerabilities.append({
                'type': 'NO_SPF_RECORD',
                'severity': 'CRITICAL',
                'description': 'Domain has no SPF record',
                'solution': 'Implement SPF record with -all policy',
                'attack_methods': [
                    'Direct email spoofing from any IP address',
                    'No authentication barrier for spammers',
                    'Easy phishing campaign setup'
                ]
            })
            return vulnerabilities

        loop_vulnerabilities = check_spf_recursion_loops(spf_record, domain)
        vulnerabilities.extend(loop_vulnerabilities)

        includes = spf_record.count('include:')
        arecords = spf_record.count(' a:') + spf_record.count(' a/') + spf_record.count(' +a ') + spf_record.count(
            ' a ')
        mxrecords = spf_record.count(' mx:') + spf_record.count(' mx/') + spf_record.count(' +mx ') + spf_record.count(
            ' mx ')
        ptrrecords = spf_record.count(' ptr:') + spf_record.count(' ptr ')
        existsrecords = spf_record.count(' exists:') + spf_record.count(' exists ')
        redirectrecords = spf_record.count(' redirect=')

        totalrecordsspf = includes + arecords + mxrecords + ptrrecords + existsrecords + redirectrecords

        if totalrecordsspf > 10:
            vulnerabilities.append({
                'type': f'TOO_MANY_SPF_LOOKUPS',
                'severity': 'CRITICAL',
                'SPF Records': [
                    'Includes: ' + str(includes),
                    'A Records: ' + str(arecords),
                    'MX Records: ' + str(mxrecords),
                    'PTR Records: ' + str(ptrrecords),
                    'EXISTS Records: ' + str(existsrecords),
                    'REDIRECT Records: ' + str(redirectrecords),
                ],
                'description': f'SPF records have too many lookups ({totalrecordsspf} > 10)',
                'solution': 'Reduce the number of lookups to less than 10',
                'attack_methods': [
                    'Email DOS using sending method (Spam or reject)',
                    'SPF bypass (Pass to Soft Fail)',
                ]
            })

        spf_lower = spf_record.lower()

        if re.search(r'[\s+]?\+\s*all\s*', spf_lower):
            vulnerabilities.append({
                'type': 'PASS_ALL_POLICY',
                'severity': 'CRITICAL',
                'description': '+all allows ANY IP to send emails for this domain',
                'solution': 'Change to -all to reject unauthorized senders',
                'attack_methods': [
                    'Send spoofed emails from any mail server',
                    'No IP restrictions for spammers',
                    'Complete domain impersonation'
                ]
            })
        elif re.search(r'[\s+]?\?\s*all\s*', spf_lower):
            vulnerabilities.append({
                'type': 'NEUTRAL_ALL_POLICY',
                'severity': 'HIGH',
                'description': '?all results in neutral for non-listed IPs',
                'solution': 'Change to -all to explicitly reject unauthorized senders',
                'attack_methods': [
                    'SPF passes as neutral for any IP',
                    'Emails not blocked by SPF checks',
                    'Relies on other security measures'
                ]
            })
        elif not 'all' in spf_record:
            vulnerabilities.append({
                'type': 'NO_ALL_MECHANISM',
                'severity': 'HIGH',
                'description': 'There is no all mechanism in the record. It may be possible'
                  ' to spoof the domain without causing an SPF failure',
                'solution': 'Add -all mechanism for strict rejection',
                'attack_methods': [
                    'Emails may be delivered to spam folder',
                    'No SPF Failure',
                    'Not protection mechanism'
                ]
            })
        elif re.search(r'[\s+]?~\s*all\s*', spf_lower):
            vulnerabilities.append({
                'type': 'SOFTFAIL_POLICY',
                'severity': 'MEDIUM',
                'description': '~all marks as softfail but doesnt reject emails - spoofed emails may be delivered',
                'solution': 'Change to -all for strict rejection',
                'attack_methods': [
                    'Emails may be delivered to spam folder',
                    'Some receivers accept softfail emails',
                    'Not a complete protection mechanism'
                ]
            })
        elif re.search(r'[\s+]?-\s*all\s*', spf_lower):
            print_good("SPF policy: STRICT (-all) - Good configuration")
            print()

        mechanisms = re.findall(r'([+~?\-]?)\s*([a-z][^:\s]*)', spf_record)
        mechanism_names = [mech[1] for mech in mechanisms]

        if 'a' in mechanism_names or 'mx' in mechanism_names:
            vulnerabilities.append({
                'type': 'BROAD_MECHANISMS',
                'severity': 'HIGH',
                'description': 'Uses a or mx mechanisms - any domain IP can send emails',
                'solution': 'Specify exact IP ranges instead of a/mx',
                'attack_methods': [
                    'Compromise any server in domain to send emails',
                    'Wide attack surface for domain infrastructure',
                    'Difficult to monitor all authorized senders'
                ]
            })

        includes = re.findall(r'include:([^\s]+)', spf_record)
        for include in includes:
            try:
                incl_answers = resolver.resolve(include, 'TXT')
                for rdata in incl_answers:
                    record_inc = ''.join([str(txt) for txt in rdata.strings])
                    if 'v=spf1' in record_inc:
                        if re.search(r'[\s+]?\+\s*all\s*', record_inc.lower()) or re.search(r'[\s+]?\?\s*all\s*',
                                                                                            record_inc.lower()):
                            vulnerabilities.append({
                                'type': 'VULNERABLE_INCLUDE',
                                'severity': 'HIGH',
                                'description': f'Included domain {include} has weak SPF',
                                'solution': f'Audit and fix SPF for {include}',
                                'attack_methods': [
                                    f'Exploit weak SPF in {include} to spoof main domain',
                                    'Chain of trust vulnerability',
                                    'Dependency attack vector'
                                ]
                            })

            except dns.resolver.Timeout:
                vulnerabilities.append({
                    'type': 'DNS_TIMEOUT',
                    'severity': 'LOW',
                    'description': f'DNS timeout when checking included domain {include}',
                    'solution': 'Check DNS configuration for included domains',
                    'attack_methods': [
                        'SPF validation may fail for included domains',
                        'Incomplete SPF chain validation',
                        'Potential authentication gaps'
                    ]
                })
            except:
                pass

        if re.search(r'[\s+]?[+~?\-]?\s*ptr\s*', spf_lower):
            vulnerabilities.append({
                'type': 'PTR_MECHANISMS',
                'severity': 'MEDIUM',
                'description': 'Uses PTR mechanism which is obsolete and unreliable',
                'solution': 'Remove PTR and use ip4/ip6 mechanisms',
                'attack_methods': [
                    'PTR records can be easily forged',
                    'DNS manipulation attacks',
                    'Unreliable authentication method'
                ]
            })

        ip_ranges = re.findall(r'ip4:([\d./]+)', spf_record)
        for ip_range in ip_ranges:
            if '/8' in ip_range or '/16' in ip_range:
                vulnerabilities.append({
                    'type': 'BROAD_IP_RANGE',
                    'severity': 'MEDIUM',
                    'description': f'Very broad IP range: {ip_range}',
                    'solution': 'Use specific IP ranges (/24 or smaller)',
                    'attack_methods': [
                        'Find available IP within large range',
                        'Difficult to monitor all IPs in range',
                        'Wide attack surface for IP spoofing'
                    ]
                })

        if len(includes) > 8:
            vulnerabilities.append({
                'type': 'COMPLEX_SPF',
                'severity': 'LOW',
                'description': 'SPF too complex - may cause DNS timeouts',
                'solution': 'Reduce number of includes and mechanisms',
                'attack_methods': [
                    'DNS timeout attacks during email verification',
                    'Performance degradation for email receivers',
                    'Potential SPF evaluation failures'
                ]
            })

        if re.search(r'redirect\s*=', spf_lower):
            redirects = re.findall(r'redirect\s*=\s*([^\s]+)', spf_record)
            for redirect in redirects:
                vulnerabilities.append({
                    'type': 'SPF_REDIRECT',
                    'severity': 'MEDIUM',
                    'description': f'Uses redirect to {redirect}',
                    'solution': 'Monitor redirect target for changes',
                    'attack_methods': [
                        f'If {redirect} SPF becomes weak, main domain affected',
                        'Redirect chain vulnerabilities',
                        'Dependency on external domain security'
                    ]
                })


        suspicious = analyze_suspicious_txt_records(all_txt_records)
        for suspicious_rec in suspicious:
            vulnerabilities.append({
                'type': f'SUSPICIOUS_TXT_RECORD_{suspicious_rec["type"]}',
                'severity': suspicious_rec['risk'],
                'description': f'Suspicious TXT record: {suspicious_rec["description"]}',
                'solution': 'Investigate and remove unnecessary TXT records',
                'attack_methods': [
                    'Data exfiltration through DNS tunneling',
                    'Command and control communication',
                    'Hidden data storage in DNS records',
                    'Malware communication channel'
                ]
            })

    except dns.resolver.Timeout:
        vulnerabilities.append({
            'type': 'DNS_TIMEOUT',
            'severity': 'LOW',
            'description': f'DNS timeout during SPF scan of {domain}',
            'solution': 'Check DNS servers and network connectivity',
            'attack_methods': [
                'SPF temperror may cause email delivery issues',
                'Inconsistent authentication results',
                'Emails may be marked as spam'
            ]
        })
    except dns.resolver.NXDOMAIN:
        vulnerabilities.append({
            'type': 'DOMAIN_NOT_RESOLVED',
            'severity': 'HIGH',
            'description': 'Domain does not exist or cannot be resolved',
            'solution': 'Check domain name and DNS configuration',
            'attack_methods': [
                'Domain may be available for registration',
                'DNS configuration issues',
                'Potential for domain takeover'
            ]
        })
    except Exception as e:
        pass

    return vulnerabilities

def dmarc_scan(domain):
    vulnerabilities = []
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_record = None
        for rdata in answers:
            record = ''.join([str(txt) for txt in rdata.strings])
            if 'v=DMARC1' in record:
                dmarc_record = record
                break
        if dmarc_record:
            print("DMARC Record Found:")
            print()
            print_low(f"DMARC Record: {dmarc_record}")
            print()
        if dmarc_record:
            fields = {}
            for field in dmarc_record.split(';'):
                field = field.strip()
                if '=' in field:
                    key, value = field.split('=', 1)
                    fields[key.strip()] = value.strip()

            adkim_value = fields.get('adkim', 'r')
            if adkim_value == 's':
                print_good("DMARC DKIM Alignment: strict")
            else:
                vulnerabilities.append({
                    'type': 'RELAXED_DKIM_ALIGNMENT',
                    'severity': 'MEDIUM',
                    'description': 'DKIM alignment set to relaxed (adkim=r) – allows subdomain spoofing',
                    'solution': 'Set adkim=s for strict alignment',
                    'attack_methods': [
                        'Subdomain email spoofing may pass DMARC',
                        'Weaker sender validation',
                        'Easier phishing via subdomains'
                    ]
                })

            aspf_value = fields.get('aspf', 'r')
            if aspf_value == 's':
                print_good("DMARC SPF Alignment: strict")
            else:
                vulnerabilities.append({
                    'type': 'RELAXED_SPF_ALIGNMENT',
                    'severity': 'MEDIUM',
                    'description': 'SPF alignment set to relaxed (aspf=r) – allows subdomain spoofing',
                    'solution': 'Set aspf=s for strict alignment',
                    'attack_methods': [
                        'Subdomain spoofing with valid SPF may pass DMARC',
                        'Reduced domain ownership enforcement',
                        'Email impersonation via delegated subdomains'
                    ]
                })

            fo_value = fields.get('fo', '0')
            if fo_value == '0':
                vulnerabilities.append({
                    'type': 'DMARC_FAILURE_REPORTING_LIMITED',
                    'severity': 'LOW',
                    'description': 'DMARC only reports when ALL mechanisms fail (fo=0) – reduces visibility',
                    'solution': 'Use fo=1 to report on ANY mechanism failure',
                    'attack_methods': [
                        'Partial authentication bypasses go undetected',
                        'Limited forensic data for incident response'
                    ]
                })
            elif fo_value == '1':
                print_good("DMARC Failure Reporting: reports on any mechanism failure (fo=1)")
            else:
                print_info(f"DMARC Failure Reporting: custom policy ({fo_value})")

            if 'rf' in fields:
                print_info(f"DMARC Report Format: {fields['rf']}")

            ri_seconds = int(fields.get('ri', '86400'))
            if ri_seconds > 86400:
                vulnerabilities.append({
                    'type': 'DMARC_INFREQUENT_REPORTING',
                    'severity': 'LOW',
                    'description': f'DMARC reports sent every {ri_seconds} seconds ({ri_seconds//3600}h) – too infrequent',
                    'solution': 'Set ri=86400 (24h) or lower for timely alerts',
                    'attack_methods': [
                        'Delayed detection of spoofing campaigns',
                        'Reduced operational visibility'
                    ]
                })
            else:

                pass

            if 'rua' in fields:
                rua_addresses = fields['rua'].split(',')
                for address in rua_addresses:
                    if 'mailto:' in address:
                        email = address.split('mailto:')[1]
                        email_domain = email.split('@')[1]
                        if email_domain != domain and not email_domain.endswith('.' + domain):
                            try:
                                auth_domain = f"{domain}._report._dmarc.{email_domain}"
                                auth_records = dns.resolver.resolve(auth_domain, 'TXT')
                                auth_found = False
                                for auth_rdata in auth_records:
                                    auth_record = ''.join([str(txt) for txt in auth_rdata.strings])
                                    if 'v=DMARC1' in auth_record:
                                        auth_found = True
                                        break
                                if not auth_found:
                                    vulnerabilities.append({
                                        'type': 'MISSING_EXTERNAL_REPORT_AUTH',
                                        'severity': 'MEDIUM',
                                        'description': f'Missing authorization record for external DMARC reports to {email_domain}',
                                        'solution': f'Add TXT record {auth_domain} with value "v=DMARC1"',
                                        'attack_methods': [
                                            'External reports may be rejected',
                                            'Loss of DMARC reporting visibility',
                                            'Incomplete email security monitoring'
                                        ]
                                    })
                            except dns.resolver.NXDOMAIN:
                                vulnerabilities.append({
                                    'type': 'MISSING_EXTERNAL_REPORT_AUTH',
                                    'severity': 'MEDIUM',
                                    'description': f'Missing authorization record for external DMARC reports to {email_domain}',
                                    'solution': f'Add TXT record {domain}._report._dmarc.{email_domain} with value "v=DMARC1"',
                                    'attack_methods': [
                                        'External reports may be rejected',
                                        'Loss of DMARC reporting visibility',
                                        'Incomplete email security monitoring'
                                    ]
                                })
                            except Exception:
                                pass
        else:

            vulnerabilities.append({
                'type': 'NO_DMARC_RECORD',
                'severity': 'HIGH',
                'description': 'Domain has no DMARC record',
                'solution': 'Implement DMARC record with reject policy',
                'attack_methods': [
                    'Email spoofing without DMARC protection',
                    'Phishing campaigns impersonating the domain',
                    'No email authentication enforcement'
                ]
            })
            return vulnerabilities

        policy_match = re.search(r'p=([^;]+)', dmarc_record)
        if policy_match:
            policy = policy_match.group(1).lower()
            if policy == 'none':
                vulnerabilities.append({
                    'type': 'DMARC_POLICY_NONE',
                    'severity': 'HIGH',
                    'description': 'DMARC policy set to none - no enforcement',
                    'solution': 'Change policy to quarantine or reject',
                    'attack_methods': [
                        'Email spoofing still possible',
                        'Phishing emails delivered to inbox',
                        'No protection against domain impersonation'
                    ]
                })
            elif policy == 'quarantine':
                vulnerabilities.append({
                    'type': 'DMARC_POLICY_QUARANTINE',
                    'severity': 'MEDIUM',
                    'description': 'DMARC policy set to quarantine - emails go to spam',
                    'solution': 'Consider moving to reject policy for better protection',
                    'attack_methods': [
                        'Emails may still be delivered to spam folder',
                        'Users might check spam folder and find malicious emails',
                        'Less protection than reject policy'
                    ]
                })
            elif policy == 'reject':
                print_good("DMARC policy: REJECT - Good configuration")
                print()

        sp_match = re.search(r'sp=([^;]+)', dmarc_record)
        if sp_match:
            sp_policy = sp_match.group(1).lower()
            if sp_policy == 'none':
                vulnerabilities.append({
                    'type': 'DMARC_SUBDOMAIN_POLICY_NONE',
                    'severity': 'HIGH',
                    'description': 'DMARC subdomain policy set to none',
                    'solution': 'Set sp=reject for subdomain protection',
                    'attack_methods': [
                        'Subdomain spoofing attacks',
                        'Phishing using subdomains',
                        'Weaker protection for subdomains'
                    ]
                })
        else:
            vulnerabilities.append({
                'type': 'NO_DMARC_SUBDOMAIN_POLICY',
                'severity': 'MEDIUM',
                'description': 'No explicit DMARC subdomain policy defined',
                'solution': 'Set sp=reject to explicitly protect subdomains',
                'attack_methods': [
                    'Subdomains inherit main domain policy which may be weak',
                    'Unclear subdomain protection',
                    'Potential subdomain spoofing'
                ]
            })

        email_related_subdomains = [
            'mail', 'email', 'smtp', 'mx', 'mx1', 'mx2', 'mx3',
            'newsletter', 'marketing', 'campaign', 'bulk', 'transactional',
            'notifications', 'alerts', 'noreply', 'contact', 'info',
            'support', 'help', 'service', 'admin', 'administrator'
        ]
        subs_without_dmarc = []
        for sub in email_related_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                try:
                    dns.resolver.resolve(subdomain, 'A')
                    exists = True
                except:
                    try:
                        dns.resolver.resolve(subdomain, 'MX')
                        exists = True
                    except:
                        exists = False
                if exists:
                    sub_dmarc_domain = f"_dmarc.{subdomain}"
                    try:
                        dns.resolver.resolve(sub_dmarc_domain, 'TXT')
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                        subs_without_dmarc.append(subdomain)
            except Exception:
                continue
        if subs_without_dmarc:
            vulnerabilities.append({
                'type': 'ACTIVE_SUBDOMAINS_WITHOUT_DMARC',
                'severity': 'MEDIUM',
                'description': f'Active email-related subdomains without DMARC: {", ".join(subs_without_dmarc[:3])}',
                'solution': 'Implement DMARC records for all active subdomains',
                'attack_methods': [
                    'Email spoofing from unprotected subdomains',
                    'Subdomain-level phishing attacks',
                    'No email authentication for subdomain services'
                ]
            })

        if 'rua' not in fields:
            vulnerabilities.append({
                'type': 'NO_DMARC_REPORTING',
                'severity': 'LOW',
                'description': 'No DMARC aggregate reporting configured (missing rua)',
                'solution': 'Add rua=mailto:security@yourdomain.com to receive reports',
                'attack_methods': [
                    'No visibility into spoofing attempts',
                    'Blind to email authentication failures',
                    'Inability to improve email security posture'
                ]
            })

        pct_match = re.search(r'pct=([^;]+)', dmarc_record)
        if pct_match:
            pct = int(pct_match.group(1))
            if pct < 100:
                vulnerabilities.append({
                    'type': 'DMARC_SAMPLING',
                    'severity': 'MEDIUM',
                    'description': f'DMARC only applied to {pct}% of emails',
                    'solution': 'Set pct=100 for full protection',
                    'attack_methods': [
                        'Some spoofed emails may bypass DMARC',
                        'Partial protection only',
                        'Attackers might get lucky with non-sampled emails'
                    ]
                })

    except dns.resolver.NXDOMAIN:
        vulnerabilities.append({
            'type': 'NO_DMARC_RECORD',
            'severity': 'HIGH',
            'description': 'Domain has no DMARC record (NXDOMAIN)',
            'solution': 'Implement DMARC record with reject policy',
            'attack_methods': [
                'Email spoofing without DMARC protection',
                'Phishing campaigns impersonating the domain',
                'No email authentication enforcement'
            ]
        })
    except dns.resolver.NoAnswer:
        vulnerabilities.append({
            'type': 'NO_DMARC_RECORD',
            'severity': 'HIGH',
            'description': 'Domain has no DMARC record (NoAnswer)',
            'solution': 'Implement DMARC record with reject policy',
            'attack_methods': [
                'Email spoofing without DMARC protection',
                'Phishing campaigns impersonating the domain',
                'No email authentication enforcement'
            ]
        })
    except dns.resolver.Timeout:
        vulnerabilities.append({
            'type': 'DMARC_CHECK_TIMEOUT',
            'severity': 'MEDIUM',
            'description': 'DMARC check timed out - cannot determine configuration',
            'solution': 'Retry DMARC check or use different DNS resolver',
            'attack_methods': [
                'Indeterminate DMARC status - proceed with caution',
                'May indicate DNS filtering or network issues'
            ]
        })
    except Exception as e:
        error_str = str(e).lower()
        if 'nxdomain' in error_str:
            vulnerabilities.append({
                'type': 'NO_DMARC_RECORD',
                'severity': 'HIGH',
                'description': f'Domain has no DMARC record: {str(e)}',
                'solution': 'Implement DMARC record with reject policy',
                'attack_methods': [
                    'Email spoofing without DMARC protection',
                    'Phishing campaigns impersonating the domain',
                    'No email authentication enforcement'
                ]
            })
        else:
            vulnerabilities.append({
                'type': 'DMARC_CHECK_FAILED',
                'severity': 'LOW',
                'description': f'Could not verify DMARC due to: {str(e)}',
                'solution': 'Check network connectivity and retry',
                'attack_methods': [
                    'DMARC status unknown - assume protection may exist',
                    'Proceed with standard email authentication testing'
                ]
            })
    return vulnerabilities

def dkimscan(domain, max_selectors=None):
    selectors = dselectors()
    if max_selectors:
        selectors = selectors[:max_selectors]
    dkimfound = []

    total = len(selectors)
    bar_length = 30

    for i, selector in enumerate(selectors):
        dkim_record = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_record, 'TXT', lifetime=2)
            record_data = ''.join([str(txt) for txt in answers])
            if 'v=DKIM1' in record_data:
                dkimfound.append({
                    'selector': selector,
                    'record': dkim_record,
                    'data': record_data
                })
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception:
            pass

        progress = (i + 1) / total
        filled_length = int(bar_length * progress)
        bar = '█' * filled_length + ' ' * (bar_length - filled_length)
        percent = int(100 * progress)

        print(f"\r{Colors.GREEN}[{bar}]{Colors.END} {percent}% ({i + 1}/{total})", end='', flush=True)

    print("\n")
    return dkimfound


def dkimvulnscan(domain, selector, record_data):

    print()
    print_low(f"Analyzing: {selector}._domainkey.{domain}")
    print_low(f"Record: {record_data}")
    print()

    vulns = []
    record_lower = record_data.lower()

    dkim_details = analyze_dkim_record_detailed(selector, record_data, domain)

    for issue in dkim_details['issues']:
        severity = 'MEDIUM'
        if dkim_details['security_level'] == 'Low':
            severity = 'HIGH'
        elif 'weak' in issue.lower() or 'testing mode' in issue.lower():
            severity = 'HIGH'

        vulns.append({
            'type': 'DKIM_CONFIGURATION_ISSUE',
            'severity': severity,
            'description': issue,
            'solution': dkim_details['recommendations'][dkim_details['issues'].index(issue)] if dkim_details[
                'recommendations'] else 'Review DKIM configuration',
            'attack_methods': [
                'Potential DKIM bypass due to misconfiguration',
                'Email spoofing attacks',
                'Reduced email authentication effectiveness'
            ]
        })

    if dkim_details.get('key_size'):
        if dkim_details['key_size'] < 1024:
            vulns.append({
                'type': 'WEAK_DKIM_KEY',
                'severity': 'CRITICAL',
                'description': f'Very weak RSA key (estimated {dkim_details["key_size"]} bits)',
                'solution': 'Use RSA keys of at least 2048 bits',
                'attack_methods': [
                    'RSA key factorization attacks',
                    'Brute force private key calculation',
                    'DKIM signature forgery'
                ]
            })
        elif dkim_details['key_size'] < 2048:
            vulns.append({
                'type': 'MODERATE_DKIM_KEY',
                'severity': 'HIGH',
                'description': f'RSA key of ~{dkim_details["key_size"]} bits - below current standard',
                'solution': 'Upgrade to 2048-bit RSA key or higher',
                'attack_methods': [
                    'Computational attacks on RSA-1024',
                    'Future proofing attacks as computing power increases'
                ]
            })

    if dkim_details['testing_mode']:
        vulns.append({
            'type': 'DKIM_TESTING_MODE',
            'severity': 'MEDIUM',
            'description': 'DKIM in testing mode (t=y) - receivers may ignore signature failures',
            'solution': 'Remove t=y for production',
            'attack_methods': [
                'Email spoofing attacks where invalid signatures are ignored',
                'Bypass DKIM verification during phishing campaigns',
                'Test malicious email templates without triggering alerts'
            ]
        })

    if 'sha1' in dkim_details['hash_algorithms'] and 'sha256' not in dkim_details['hash_algorithms']:
        vulns.append({
            'type': 'WEAK_HASH_ALGORITHM',
            'severity': 'HIGH',
            'description': 'Uses SHA1 algorithm which is considered weak',
            'solution': 'Update to use SHA-256 algorithm',
            'attack_methods': [
                'SHA1 collision attacks',
                'Hash length extension attacks',
                'Cryptographic brute force attacks'
            ]
        })

    if re.search(r'\bt=y\b', record_lower) or re.search(r'\bt=Y\b', record_lower):
        pass

    g_match = re.search(r'\bg=([^;]+)', record_lower)
    if g_match:
        g_value = g_match.group(1)
        if g_value != '*':
            vulns.append({
                'type': 'OPEN_SUBDOMAIN_POLICY',
                'severity': 'HIGH',
                'description': f'Subdomain policy allows: {g_value}',
                'solution': 'Use g=* to restrict to main domain only',
                'attack_methods': [
                    'Create malicious subdomains to send authenticated emails',
                    'Subdomain takeover attacks for email spoofing',
                    'Use any subdomain for phishing campaigns'
                ]
            })
    else:
        vulns.append({
            'type': 'NO_SUBDOMAIN_POLICY',
            'severity': 'MEDIUM',
            'description': 'No subdomain policy defined (g tag missing)',
            'solution': 'Add g=* to prevent use on subdomains',
            'attack_methods': [
                'Unrestricted subdomain usage for email attacks',
                'Easy domain impersonation through subdomains'
            ]
        })

    h_match = re.search(r'\bh=([^;]+)', record_lower)
    if h_match:
        headers = h_match.group(1).split(':')
        critical_headers = ['from', 'to', 'subject', 'date', 'message-id']
        for critical_header in critical_headers:
            if critical_header not in [h.lower() for h in headers]:
                vulns.append({
                    'type': 'CRITICAL_HEADER_NOT_SIGNED',
                    'severity': 'HIGH',
                    'description': f'Critical header "{critical_header}" is not being signed',
                    'solution': f'Include {critical_header} in the signed headers list (h=)',
                    'attack_methods': [
                        f'Modify {critical_header} without breaking DKIM signature',
                        'Email header injection attacks',
                        'Spoof critical email metadata'
                    ]
                })

    c_match = re.search(r'\bc=([^/]+)/([^;]+)', record_lower)
    if c_match:
        header_canon = c_match.group(1)
        body_canon = c_match.group(2)
        if header_canon == 'simple' and body_canon == 'simple':
            vulns.append({
                'type': 'DOUBLE_SIMPLE_CANONICALIZATION',
                'severity': 'MEDIUM',
                'description': 'Double simple canonicalization - susceptible to modifications',
                'solution': 'Use c=relaxed/relaxed for better tolerance',
                'attack_methods': [
                    'Whitespace manipulation attacks',
                    'Header rewriting without signature break',
                    'Email content modification attacks'
                ]
            })
    else:
        vulns.append({
            'type': 'NO_CANONICALIZATION_DEFINED',
            'severity': 'LOW',
            'description': 'No canonicalization method specified',
            'solution': 'Define c=relaxed/relaxed',
            'attack_methods': [
                'Unpredictable signature verification behavior',
                'Potential canonicalization mismatch attacks'
            ]
        })

    p_match = re.search(r'\bp=([^;\s]+)', record_lower)
    if p_match:
        public_key = p_match.group(1)
        try:
            import base64
            key_bytes = base64.b64decode(public_key + '=' * (-len(public_key) % 4))
            key_length = len(key_bytes) * 8
        except:
            key_length = (len(public_key) * 6) // 8 * 8

        if key_length < 1024:
            vulns.append({
                'type': 'WEAK_RSA_KEY',
                'severity': 'CRITICAL',
                'description': f'Potentially weak RSA key (estimated {key_length} bits)',
                'solution': 'Use RSA keys of at least 2048 bits',
                'attack_methods': [
                    'RSA key factorization attacks',
                    'Brute force private key calculation',
                    'DKIM signature forgery'
                ]
            })
        elif key_length < 2048:
            vulns.append({
                'type': 'SHORT_RSA_KEY',
                'severity': 'HIGH',
                'description': f'RSA key of ~{key_length} bits - below current standard',
                'solution': 'Upgrade to 2048-bit RSA key or higher',
                'attack_methods': [
                    'Computational attacks on RSA-1024',
                    'Future proofing attacks as computing power increases'
                ]
            })

    if not re.search(r'\bv=dkim1;', record_lower):
        vulns.append({
            'type': 'INVALID_VERSION',
            'severity': 'HIGH',
            'description': 'DKIM version not specified or invalid',
            'solution': 'Use v=DKIM1;',
            'attack_methods': [
                'Version confusion attacks',
                'Backward compatibility exploitation',
                'Parser implementation vulnerabilities'
            ]
        })

    if re.search(r'\bk=rsa-sha1\b', record_lower):
        vulns.append({
            'type': 'OBSOLETE_SHA1_ALGORITHM',
            'severity': 'HIGH',
            'description': 'Uses SHA1 algorithm which is considered weak',
            'solution': 'Update to k=rsa-sha256;',
            'attack_methods': [
                'SHA1 collision attacks',
                'Hash length extension attacks',
                'Cryptographic brute force attacks'
            ]
        })

    if h_match:
        headers = h_match.group(1).split(':')
        if 'from' not in [h.lower() for h in headers]:
            vulns.append({
                'type': 'FROM_HEADER_NOT_SIGNED',
                'severity': 'CRITICAL',
                'description': 'FROM header not signed - allows complete sender spoofing',
                'solution': 'Always include "from" in signed headers',
                'attack_methods': [
                    'Complete email sender impersonation',
                    'Phishing attacks with legitimate DKIM signatures',
                    'Business Email Compromise (BEC) attacks'
                ]
            })

    s_match = re.search(r'\bs=([^;]+)', record_lower)
    if s_match:
        service_type = s_match.group(1)
        if service_type != '*':
            vulns.append({
                'type': 'RESTRICTED_SERVICE_TYPE',
                'severity': 'LOW',
                'description': f'Service type restricted to: {service_type}',
                'solution': 'Consider using s=* for all email services',
                'attack_methods': [
                    'Potential compatibility issues with some email services',
                    'Limited to specific email service types'
                ]
            })

    t_match = re.search(r'\bt=([^;]+)', record_lower)
    if t_match:
        flags = t_match.group(1).split(':')
        if 's' in flags:
            vulns.append({
                'type': 'STRICT_DKIM_POLICY',
                'severity': 'LOW',
                'description': 'Strict DKIM policy enabled (t=s)',
                'solution': 'Ensure all emails are properly signed',
                'attack_methods': [
                    'Emails without DKIM signatures will be rejected',
                    'Potential delivery issues for unsigned emails'
                ]
            })

    return vulns


def analyze_suspicious_txt_records(txt_records):
    suspicious_records = []
    for record in txt_records:
        if 'v=spf1' in record or 'v=DKIM1' in record:
            continue
        record_str = str(record)
        if len(record_str) > 50 and re.match(r'^[a-z0-9]{20,}$', record_str.lower()):
            suspicious_records.append({
                'record': record_str,
                'type': 'RANDOM_STRING',
                'risk': 'HIGH',
                'description': 'Long random string that could be data exfiltration or C2 communication',
                'investigation': 'Check if this is legitimate or potential malware communication'
            })
        elif re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', record_str):
            suspicious_records.append({
                'record': record_str,
                'type': 'BASE64_ENCODED',
                'risk': 'MEDIUM',
                'description': 'Base64 encoded data - could hide malicious payloads',
                'investigation': 'Decode and analyze the content'
            })
        elif re.match(r'^[0-9a-f]{20,}$', record_str.lower()):
            suspicious_records.append({
                'record': record_str,
                'type': 'HEX_STRING',
                'risk': 'MEDIUM',
                'description': 'Hexadecimal string - could be encoded data or identifiers',
                'investigation': 'Analyze purpose and decode if necessary'
            })
    return suspicious_records


def print_vulnerability(vuln):
    severity = vuln['severity']
    title = f"{vuln['type']} [{severity}]"
    if severity == 'CRITICAL':
        print_critical(title)
    elif severity == 'HIGH':
        print_critical(title)
    elif severity == 'MEDIUM':
        print_medium(title)
    elif severity == 'LOW':
        print_low(title)
    print(f"   Description: {vuln['description']}")
    if 'SPF Records' in vuln:
        print(f"   SPF Records Details: {vuln['SPF Records']}")
    print(f"   Solution: {vuln['solution']}")
    print(f"   Attack Methods:")
    for i, attack in enumerate(vuln['attack_methods'], 1):
        print(f"     {i}. {attack}")
    print()


def generate_attack_roadmap(spf_vulns, dmarc_vulns, dkim_vulns, mx_vulns, takeover_vulns=None, email_protections=None):
    roadmap = []

    if email_protections:
        high_protection = any(p['bypass_difficulty'] == 'HIGH' for p in email_protections)
        if high_protection:
            roadmap.append("ENTERPRISE EMAIL SECURITY DETECTED - High difficulty bypass")
            roadmap.append("Attack vector: Focus on social engineering vs technical bypass")
        else:
            roadmap.append("BASIC/MEDIUM PROTECTION - Technical bypass possible")
            roadmap.append("Attack vector: Combine technical and social engineering")

    if takeover_vulns:
        roadmap.append("SUBDOMAIN TAKEOVER OPPORTUNITIES DETECTED")
        roadmap.append("Attack vector: Takeover subdomains to send authenticated emails")
        for takeover in takeover_vulns:
            roadmap.append(f"  - {takeover['domain']} -> {takeover['service']}")

    has_unregistered_spf = any('SPF_UNREGISTERED_DOMAINS' in v['type'] for v in spf_vulns)

    if has_unregistered_spf:
        roadmap.append("CRITICAL: UNREGISTERED DOMAINS IN SPF CHAIN")
        roadmap.append("Attack vector: Register the unregistered domains and configure malicious SPF records")
        roadmap.append("Impact: Complete email spoofing bypass - most critical finding")

    has_no_spf = any(v['type'] == 'NO_SPF_RECORD' for v in spf_vulns)
    has_spf_weak = any(v['type'] in ['PASS_ALL_POLICY', 'NEUTRAL_ALL_POLICY', 'SOFTFAIL_POLICY'] for v in spf_vulns)
    has_no_dmarc = any(v['type'] == 'NO_DMARC_RECORD' for v in dmarc_vulns)
    has_dmarc_none = any(v['type'] == 'DMARC_POLICY_NONE' for v in dmarc_vulns)
    has_dmarc_quarantine = any(v['type'] == 'DMARC_POLICY_QUARANTINE' for v in dmarc_vulns)
    has_broad_mechanisms = any(v['type'] == 'BROAD_MECHANISMS' for v in spf_vulns)

    if has_no_spf and has_no_dmarc:
        roadmap.append("DIRECT SPOOFING: No SPF and no DMARC protection allows direct email spoofing from any IP")
        roadmap.append("Attack vector: Send spoofed emails directly to targets")
    elif has_spf_weak and has_dmarc_none:
        roadmap.append("SPF BYPASS + DMARC NONE: Weak SPF combined with no DMARC enforcement")
        roadmap.append("Attack vector: Use IPs not in SPF record to send spoofed emails")
    elif has_broad_mechanisms and has_dmarc_quarantine:
        roadmap.append("BROAD SPF + DMARC QUARANTINE: Wide SPF range with quarantine-only DMARC")
        roadmap.append("Attack vector: Compromise any domain server or find IP in broad range, emails may reach spam")
    elif has_dmarc_quarantine:
        roadmap.append("DMARC QUARANTINE: Emails go to spam but not rejected")
        roadmap.append("Attack vector: Social engineering to check spam folder or combined with other attacks")
    elif has_no_dmarc:
        roadmap.append("NO DMARC: No email authentication enforcement")
        roadmap.append("Attack vector: Spoof emails focusing on bypassing SPF only")
    else:
        roadmap.append("TARGET HARDENED: Multiple layers of protection present")
        roadmap.append("Attack vector: Consider alternative approaches or target weaker subdomains")

    if any('SUBDOMAIN' in v['type'] for v in spf_vulns + dmarc_vulns + dkim_vulns):
        roadmap.append("SUBDOMAIN ATTACK: Weak subdomain policies allow subdomain spoofing")
        roadmap.append("Attack vector: Use subdomains to bypass main domain protections")

    if any('RELAXED' in v['type'] for v in dmarc_vulns):
        roadmap.append("RELAXED ALIGNMENT: SPF/DKIM alignment not strict")
        roadmap.append("Attack vector: Exploit relaxed alignment for domain spoofing")

    if email_protections:
        protection_names = [p['service'] for p in email_protections]
        roadmap.append(f"DETECTED SERVICES: {', '.join(protection_names)}")

        if 'Proofpoint' in protection_names:
            roadmap.append("Proofpoint bypass: Consider attachment-based attacks or URL redirection")
        if 'Mimecast' in protection_names:
            roadmap.append("Mimecast bypass: Focus on content obfuscation and time-based attacks")
        if 'Microsoft Defender' in protection_names:
            roadmap.append("Microsoft Defender: Use macro-less attacks and living-off-the-land techniques")

    return roadmap


def scan_domain(domain, max_selectors=500, enable_takeover_scan=True, no_output=False, save_output=False):
    if not no_output:
        print()
        print("=" * 70)
        print(f"Starting Email Security Full Scan for: {domain}")
        print("=" * 70)

    start_time = time.time()

    total_vulnerabilities = 0
    vulnerability_breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    sources_breakdown = {'SPF': [], 'DMARC': [], 'DKIM': [], 'MX': [], 'TAKEOVER': []}

    dkim_vulns = []
    takeover_vulns = []

    scan_results = {
        'mxanalyzer': {
            'domain': domain,
            'scan_timestamp': time.time(),
            'scan_duration': 0,
            'total_vulnerabilities': 0,
            'vulnerability_breakdown': vulnerability_breakdown.copy(),
            'sources_breakdown': {k: [] for k in sources_breakdown.keys()},
            'nameservers': [],
            'mx_servers': [],
            'email_protections': [],
            'spf_vulnerabilities': [],
            'dmarc_vulnerabilities': [],
            'dkim_vulnerabilities': [],
            'takeover_vulnerabilities': [],
            'attack_roadmap': []
        }
    }


    if not no_output:
        print("\n" + "=" * 50)
        print("DNS & INFRASTRUCTURE ANALYSIS")
        print("=" * 50)
        print()

    nameservers = get_nameservers(domain)
    scan_results['mxanalyzer']['nameservers'] = nameservers

    if not no_output:
        if nameservers:
            print_low(f"Found {len(nameservers)} nameservers:")
            print()
            for i, ns in enumerate(nameservers, 1):
                print(f"  {i}. {ns}")
        else:
            print("No nameservers found")
            print()

    mx_servers, mx_vulns = get_mx_servers(domain)
    scan_results['mxanalyzer']['mx_servers'] = mx_servers
    total_vulnerabilities += len(mx_vulns)
    if not no_output and mx_vulns:
        for vuln in mx_vulns:
            print_vulnerability(vuln)
    for vuln in mx_vulns:
        vulnerability_breakdown[vuln['severity']] += 1
        sources_breakdown['MX'].append(vuln['type'])
        scan_results['mxanalyzer']['sources_breakdown']['MX'].append(vuln['type'])

    if enable_takeover_scan:
        if not no_output:
            print("\n" + "=" * 50)
            print("SUBDOMAIN TAKEOVER ANALYSIS")
            print("=" * 50)
            print()
            print(f"Checking subdomains for takeover vulnerabilities...")
            print()

        takeover_vulns = subdomain_takeover_scan(domain)
        total_vulnerabilities += len(takeover_vulns)
        scan_results['mxanalyzer']['takeover_vulnerabilities'] = takeover_vulns
        for vuln in takeover_vulns:
            vulnerability_breakdown['HIGH'] += 1
            sources_breakdown['TAKEOVER'].append(f"{vuln['service']}_TAKEOVER")
            scan_results['mxanalyzer']['sources_breakdown']['TAKEOVER'].append(f"{vuln['service']}_TAKEOVER")

        if not no_output:
            if takeover_vulns:
                print_critical(f"Found {len(takeover_vulns)} vulnerable subdomains:")
                print()
                for result in takeover_vulns:
                    print_critical(f"VULNERABLE: {result['domain']}")
                    print(f"   Service: {result['service']}")
                    print(f"   CNAME: {result['cname_record']}")
                    print(f"   Status: {result['status']}")
                    if result['fingerprint']:
                        print(f"   Fingerprint: {result['fingerprint']}")
                    if result['response_body']:
                        print(f"   Response: {result['response_body']}")
                    print()
            else:
                print_good("No subdomain takeover issues detected")
                print()

    if not no_output:
        print("\n" + "=" * 50)
        print("EMAIL SECURITY SERVICES DETECTION")
        print("=" * 50)
        print()

    email_protections = detect_protections(domain)
    scan_results['mxanalyzer']['email_protections'] = email_protections

    if not no_output:
        if email_protections:
            print_low("Detected Email Security Services:")
            print()
            for protection in email_protections:
                severity = protection['bypass_difficulty']
                if severity == 'HIGH':
                    print_critical(f"  {protection['service']} - {protection['type']}")
                elif severity == 'MEDIUM':
                    print_medium(f"  {protection['service']} - {protection['type']}")
                else:
                    print_low(f"  {protection['service']} - {protection['type']}")
                    print(f"     Description: {protection['description']}")
                    print(f"     Bypass Difficulty: {protection['bypass_difficulty']}")
                    print(f"     Detection: {protection['detection_method']}")
                    if 'server' in protection:
                        print(f"     Server: {protection['server']}")
                    print()
    else:
            print_good("No enterprise email security services detected")

    if not no_output:
        print("\n" + "=" * 50)
        print("EMAIL AUTHENTICATION ANALYSIS")
        print("=" * 50)
        print()

        print("\n" + "-" * 20)
        print("SPF SCAN RESULTS")
        print("-" * 20)
        print()

    spf_vulns = spf_scan(domain)
    scan_results['mxanalyzer']['spf_vulnerabilities'] = spf_vulns
    total_vulnerabilities += len(spf_vulns)
    if spf_vulns:
        for vuln in spf_vulns:
            if not no_output:
                print_vulnerability(vuln)
            vulnerability_breakdown[vuln['severity']] += 1
            sources_breakdown['SPF'].append(vuln['type'])
            scan_results['mxanalyzer']['sources_breakdown']['SPF'].append(vuln['type'])
    elif not no_output:
        print_good("No SPF vulnerabilities found")

    if not no_output:
        print("\n" + "-" * 20)
        print("DMARC SCAN RESULTS")
        print("-" * 20)
        print()

    dmarc_vulns = dmarc_scan(domain)
    scan_results['mxanalyzer']['dmarc_vulnerabilities'] = dmarc_vulns
    total_vulnerabilities += len(dmarc_vulns)
    if dmarc_vulns:
        for vuln in dmarc_vulns:
            if not no_output:
                print_vulnerability(vuln)
            vulnerability_breakdown[vuln['severity']] += 1
            sources_breakdown['DMARC'].append(vuln['type'])
            scan_results['mxanalyzer']['sources_breakdown']['DMARC'].append(vuln['type'])
    elif not no_output:
        print_good("No DMARC vulnerabilities found")

    if not no_output:
        print("\n" + "-" * 20)
        print("DKIM SCAN RESULTS")
        print("-" * 20)
        print()
        print(f"Searching DKIM in {domain} using {max_selectors} selectors...")
        print("This may take a while...")
        print()

    dkim_records = dkimscan(domain, max_selectors)
    if not dkim_records:
        no_dkim_vuln = {
            'type': 'NO_DKIM_RECORDS -  NOTE: Maybe not found but not 100$ secure',
            'severity': 'HIGH',
            'description': 'Domain has no DKIM records - no email signing authentication',
            'solution': 'Implement DKIM for email signing and authentication',
            'attack_methods': [
                'Email tampering without detection',
                'No cryptographic proof of email authenticity',
                'Easier email spoofing and phishing attacks'
            ]
        }
        dkim_vulns = [no_dkim_vuln]
        if not no_output:
            print_vulnerability(no_dkim_vuln)
        total_vulnerabilities += 1
        vulnerability_breakdown['HIGH'] += 1
        sources_breakdown['DKIM'].append('NO_DKIM_RECORDS')
        scan_results['mxanalyzer']['sources_breakdown']['DKIM'].append('NO_DKIM_RECORDS')
    else:
        if not no_output:
            print()
            print(f"Found {len(dkim_records)} DKIM records")
        dkim_vulns = []
        for dkim in dkim_records:
            record_vulns = dkimvulnscan(domain, dkim['selector'], dkim['data'])
            dkim_vulns.extend(record_vulns)
            total_vulnerabilities += len(record_vulns)
            if record_vulns:
                for vuln in record_vulns:
                    if not no_output:
                        print_vulnerability(vuln)
                    vulnerability_breakdown[vuln['severity']] += 1
                    sources_breakdown['DKIM'].append(vuln['type'])
                    scan_results['mxanalyzer']['sources_breakdown']['DKIM'].append(vuln['type'])
            elif not no_output:
                print_good(f"   Secure configuration for selector: {dkim['selector']}")

    scan_results['mxanalyzer']['dkim_vulnerabilities'] = dkim_vulns

    if not no_output:
        print("\n" + "-" * 20)
        print("DKIM ALIGNMENT ANALYSIS")
        print("-" * 20)
        print()

    dkim_alignment = check_dkim_alignment(domain)
    if dkim_alignment['alignment_issues']:
        for issue in dkim_alignment['alignment_issues']:

            alignment_vulnerability = {
                'type': 'DKIM_ALIGNMENT_ISSUE',
                'severity': 'MEDIUM',
                'description': issue,
                'solution': 'Ensure mail servers are properly aligned with domain',
                'attack_methods': [
                    'Email authentication inconsistencies',
                    'Potential DMARC alignment failures',
                    'Reduced email deliverability'
                ]
            }
            dkim_vulns.append(alignment_vulnerability)
            total_vulnerabilities += 1
            vulnerability_breakdown['MEDIUM'] += 1
            sources_breakdown['DKIM'].append('DKIM_ALIGNMENT_ISSUE')
            scan_results['mxanalyzer']['sources_breakdown']['DKIM'].append('DKIM_ALIGNMENT_ISSUE')

        for recommendation in dkim_alignment['recommendations']:
            print_info(f"Recommendation: {recommendation}")
    else:
        print_good("DKIM alignment: Good - Mail servers properly aligned")

    attack_roadmap = generate_attack_roadmap(spf_vulns, dmarc_vulns, dkim_vulns, mx_vulns, takeover_vulns,
                                             email_protections)
    scan_results['mxanalyzer']['attack_roadmap'] = attack_roadmap

    if not no_output:
        print("\n" + "=" * 50)
        print("ATTACK ROADMAP")
        print("=" * 50)
        print()
        for i, step in enumerate(attack_roadmap, 1):
            if i % 2 == 1:
                print_medium(step)
            else:
                print(f"   {step}")

    scan_results['mxanalyzer']['total_vulnerabilities'] = total_vulnerabilities
    scan_results['mxanalyzer']['vulnerability_breakdown'] = vulnerability_breakdown
    scan_results['mxanalyzer']['scan_duration'] = time.time() - start_time

    if not no_output:
        print("\n" + "=" * 70)
        print("SCAN SUMMARY")
        print("=" * 70)
        print()
        print(f"Domain: {domain}")
        print(f"Total Vulnerabilities Found: {total_vulnerabilities}")
        print("\nVulnerability Breakdown:")
        if vulnerability_breakdown['CRITICAL'] > 0:
            print_critical(f"  CRITICAL: {vulnerability_breakdown['CRITICAL']}")
        if vulnerability_breakdown['HIGH'] > 0:
            print_critical(f"  HIGH: {vulnerability_breakdown['HIGH']}")
        if vulnerability_breakdown['MEDIUM'] > 0:
            print_medium(f"  MEDIUM: {vulnerability_breakdown['MEDIUM']}")
        if vulnerability_breakdown['LOW'] > 0:
            print_low(f"  LOW: {vulnerability_breakdown['LOW']}")

        print("\nVulnerabilities by Source:")
        for source, vulns in sources_breakdown.items():
            if vulns:
                count = len(vulns)
                if source == 'SPF' and count > 0:
                    print(f"  SPF: {count}")
                elif source == 'DMARC' and count > 0:
                    print(f"  DMARC: {count}")
                elif source == 'DKIM' and count > 0:
                    print(f"  DKIM: {count}")
                elif source == 'MX' and count > 0:
                    print(f"  MX: {count}")
                elif source == 'TAKEOVER' and count > 0:
                    print(f"  SUBDOMAIN TAKEOVER: {count}")

        print("\nSecurity Status: ", end="")
        if total_vulnerabilities == 0:
            print_good("EXCELLENT - No vulnerabilities detected")
        elif total_vulnerabilities <= 3 and vulnerability_breakdown['CRITICAL'] == 0:
            print_good("GOOD - Minor improvements needed")
        elif total_vulnerabilities <= 7 and vulnerability_breakdown['CRITICAL'] == 0:
            print_medium("FAIR - Several security issues to address")
        else:
            print_critical("POOR - Critical security issues present")

    if save_output:
        output_dir = "output"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        filename = f"{output_dir}/{domain}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(scan_results, f, indent=2, ensure_ascii=False)

        if not no_output:
            print(f"\nResults saved to: {filename}")
            print()

    return scan_results


def main():
    parser = argparse.ArgumentParser(
        description='Email Security Scanner - Comprehensive analysis of SPF, DKIM, DMARC, MX configurations and Subdomain Takeover')
    parser.add_argument('-d', '--domain', type=str, help='Domain to scan (e.g., example.com)')
    parser.add_argument('-l', '--list', type=str, help='File containing list of domains to scan (one per line)')
    parser.add_argument('--no-takeover', action='store_true', help='Disable subdomain takeover scanning')
    parser.add_argument('--nooutput', action='store_true', help='Disable console output')
    parser.add_argument('-s', '--save', action='store_true', help='Save results to JSON files')

    args = parser.parse_args()

    if not args.domain and not args.list:
        parser.print_help()
        sys.exit(1)

    domains = []

    if args.domain:
        domains.append(args.domain)

    if args.list:
        try:
            with open(args.list, 'r') as f:
                for line in f:
                    domain = line.strip()
                    if domain and not domain.startswith('#'):
                        domains.append(domain)
        except FileNotFoundError:
            print(f"Error: File {args.list} not found")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file {args.list}: {e}")
            sys.exit(1)

    if not domains:
        print("Error: No domains to scan")
        sys.exit(1)

    for domain in domains:
        scan_domain(
            domain,
            enable_takeover_scan=not args.no_takeover,
            no_output=args.nooutput,
            save_output=args.save
        )


if __name__ == "__main__":
    main()
