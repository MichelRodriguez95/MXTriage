import dns.resolver
import re, os, random
import sys
import argparse
import signal
import requests
import json
import time


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


def load_takeover_fingerprints(json_file_path="fingerprints.json"):
    try:
        if os.path.exists(json_file_path):
            with open(json_file_path, 'r', encoding='utf-8') as f:
                fingerprints = json.load(f)
                return fingerprints
        return download_fingerprints_from_github()
    except Exception as e:
        return get_default_fingerprints()


def download_fingerprints_from_github():
    url = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        fingerprints = response.json()
        return fingerprints
    except Exception as e:
        return get_default_fingerprints()


def get_default_fingerprints():
    return [
        {
            "service": "AWS S3",
            "cname": ["s3.amazonaws.com"],
            "fingerprint": "NoSuchBucket",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "GitHub Pages",
            "cname": ["github.io"],
            "fingerprint": "There isn't a GitHub Pages site here",
            "status": "vulnerable",
            "vulnerable": True
        },
        {
            "service": "Heroku",
            "cname": ["herokuapp.com"],
            "fingerprint": "No such app",
            "status": "vulnerable",
            "vulnerable": True
        },
    ]


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

    fingerprints = load_takeover_fingerprints()
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
        'google', 'gmail', 'gsuite', 'workspace', 'googlemail',
        'selector1', 'selector2', 'selector3', 'outlook', 'microsoft', 'office365', 'exchange',
        'k1', 'k2', 'k3', 'ses', 'amazon', 'aws',
        's1', 's2', 's3', 'sendgrid', 'sg',
        'mandrill', 'mailchimp', 'mc', 'chimp',
        'mg', 'mailgun', 'email',
        'pm', 'postmark', 'pmk1',
        'sparkpost', 'sp', 'spk1',
        'zoho', 'zmail', 'zm',
        'yahoo', 'ymail', 'aol',
        'apple', 'icloud', 'mac',
        'protonmail', 'proton',
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
        '2023', '2024', '2025', '2022', '2021',
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

        if len(mx_servers) == 1:
            vulnerabilities.append({
                'type': 'SINGLE_MX_SERVER',
                'severity': 'HIGH',
                'description': 'Only one MX server - single point of failure',
                'solution': 'Add backup MX servers with lower priority',
                'attack_methods': [
                    'Targeted DDoS against single mail server',
                    'Single server compromise affects all email',
                    'No failover for email delivery'
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
        return [], vulnerabilities
    except Exception:
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
            print("SPF Record Fund:")
            print_low(f"SPF Record: {spf_record}")
            print()

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
            print_low(f"DMARC Record: {dmarc_record}")
            print()

        if not dmarc_record:
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

        rua_match = re.search(r'rua=([^;]+)', dmarc_record)
        if not rua_match:
            vulnerabilities.append({
                'type': 'NO_DMARC_REPORTING',
                'severity': 'LOW',
                'description': 'No DMARC reporting configured',
                'solution': 'Add rua tag for DMARC report reception',
                'attack_methods': [
                    'No visibility into authentication failures',
                    'Cannot monitor spoofing attempts',
                    'Limited forensic capabilities'
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

        if 'aspf=r' not in dmarc_record:
            vulnerabilities.append({
                'type': 'RELAXED_SPF_ALIGNMENT',
                'severity': 'MEDIUM',
                'description': 'SPF alignment set to relaxed instead of strict',
                'solution': 'Consider using aspf=s for strict SPF alignment',
                'attack_methods': [
                    'Subdomain spoofing might pass SPF alignment',
                    'Weaker domain alignment verification'
                ]
            })

        if 'adkim=r' not in dmarc_record:
            vulnerabilities.append({
                'type': 'RELAXED_DKIM_ALIGNMENT',
                'severity': 'MEDIUM',
                'description': 'DKIM alignment set to relaxed instead of strict',
                'solution': 'Consider using adkim=s for strict DKIM alignment',
                'attack_methods': [
                    'Subdomain DKIM might pass alignment',
                    'Weaker domain alignment verification'
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

    print()
    return dkimfound


def dkimvulnscan(domain, selector, record_data):
    print()
    print_low(f"Analyzing: {selector}._domainkey.{domain}")
    print_low(f"Record: {record_data}")
    print()
    vulns = []
    record_lower = record_data.lower()

    if re.search(r'\bt=y\b', record_lower):
        vulns.append({
            'type': 'TESTING_MODE',
            'severity': 'MEDIUM',
            'description': 'DKIM in testing mode (t=y) - receivers may ignore signature failures',
            'solution': 'Remove t=y for production',
            'attack_methods': [
                'Email spoofing attacks where invalid signatures are ignored',
                'Bypass DKIM verification during phishing campaigns',
                'Test malicious email templates without triggering alerts'
            ]
        })

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
    for vuln in mx_vulns:
        vulnerability_breakdown[vuln['severity']] += 1
        sources_breakdown['MX'].append(vuln['type'])
        scan_results['mxanalyzer']['sources_breakdown']['MX'].append(vuln['type'])

    if not no_output and mx_servers:
        print()
        print_low(f"Found {len(mx_servers)} MX servers:")
        print()
        for i, mx in enumerate(mx_servers, 1):
            print(f"  {i}. {mx['server']} (Priority: {mx['priority']})")
            for ip in mx['ips']:
                print(f"     IP: {ip}")

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
                for result in takeover_vulns:
                    print_critical(f"VULNERABLE: {result['domain']}")
                    print(f"   Service: {result['service']}")
                    print(f"   CNAME: {result['cname_record']}")
                    print(f"   Status: {result['status']}")
                    if result['fingerprint']:
                        print(f"   Fingerprint: {result['fingerprint']}")
            else:
                print_good("No subdomain takeover issues detected")

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
            for protection in email_protections:
                severity = protection['bypass_difficulty']
                if severity == 'HIGH':
                    print_critical(f"  {protection['service']} - {protection['type']}")
                elif severity == 'MEDIUM':
                    print_medium(f"  {protection['service']} - {protection['type']}")
                else:
                    print_low(f"  {protection['service']} - {protection['type']}")
                print(f"     Description: {protection['description']}")
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
            'type': 'NO_DKIM_RECORDS',
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