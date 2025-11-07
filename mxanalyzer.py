import dns.resolver
import re
import sys
import argparse
import signal

class Colors:
    RED = '\033[91m'
    ORANGE = '\033[33m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    END = '\033[0m'

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
    print(f"Analyzing Email Security Services for: {domain}")
    print()

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

        if protections:
            print_low("Detected Email Security Services:")
            for protection in protections:
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
            print("   Note: Domain may use basic protection or custom solutions")

    except Exception as e:
        print(f"   Could not analyze email security services: {e}")

    return protections

def get_nameservers(domain):
    print()
    print(f"Analyzing DNS servers for: {domain}")
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        nameservers = [str(ns.target).rstrip('.') for ns in answers]
        print_low(f"Found {len(nameservers)} nameservers:")
        for i, ns in enumerate(nameservers, 1):
            print(f"  {i}. {ns}")
        return nameservers
    except Exception:
        return []

def get_mx_servers(domain):
    print()
    print(f"Analyzing MX servers for: {domain}")
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
        print_low(f"Found {len(mx_servers)} MX servers:")
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
                    'No failover for email delivery'
                ]
            })

            print_vulnerability(vulnerabilities[-1])

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
                    print_vulnerability(vuln)

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
        print_vulnerability(vuln)
        return [], vulnerabilities
    except Exception:
        return [], vulnerabilities

def spf_scan(domain):
    print(f"Analyzing SPF for: {domain}")
    vulnerabilities = []
    all_txt_records = []
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_record = None
        print(f"Raw TXT records found: {len(answers)}")
        for rdata in answers:
            record = ''.join([str(txt) for txt in rdata.strings])
            all_txt_records.append(record)
            print(f"  Checking record: {record}")
            if 'v=spf1' in record:
                spf_record = record
                break
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
        print_low(f"SPF Record: {spf_record}")
        print()

        if '+all' in spf_record and spf_record.rstrip().endswith('+all'):
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
        elif '?all' in spf_record and spf_record.rstrip().endswith('?all'):
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
        elif '~all' in spf_record:
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
        elif '-all' in spf_record and spf_record.rstrip().endswith('-all'):
            print_good("SPF policy: STRICT (-all) - Good configuration")

        mechanisms = re.findall(r'(\+?[a-z][^:\s]*)', spf_record)
        if 'a' in mechanisms or 'mx' in mechanisms:
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
                incl_answers = dns.resolver.resolve(include, 'TXT')
                for rdata in incl_answers:
                    record_inc = ''.join([str(txt) for txt in rdata.strings])
                    if 'v=spf1' in record_inc:
                        if '+all' in record_inc or '?all' in record_inc:
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
            except:
                pass
        if 'ptr' in spf_record:
            vulnerabilities.append({
                'type': 'PTR_MECHANISM',
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
        if 'redirect' in spf_record:
            redirects = re.findall(r'redirect=([^\s]+)', spf_record)
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
    except Exception:
        pass
    return vulnerabilities

def dmarc_scan(domain):
    print(f"Analyzing DMARC for: {domain}")
    print()
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

        print_low(f"DMARC Record: {dmarc_record}")
        print()

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
    print(f"Searching DKIM in {domain} using {len(selectors)} selectors...")
    print("This may take a while...")
    dkimfound = []
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
            continue
        except Exception:
            continue
    return dkimfound

def dkimvulnscan(domain, selector, record_data):
    vulns = []
    print_low(f"Analyzing: {selector}._domainkey.{domain}")
    print_low(f"Record: {record_data}")
    print()
    if 't=y' in record_data or 't=Y' in record_data:
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
    g_match = re.search(r'g=([^;]+);', record_data)
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
    h_match = re.search(r'h=([^;]+);', record_data)
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
    c_match = re.search(r'c=([^/]+)/([^;]+);', record_data)
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
    p_match = re.search(r'p=([^;]+)', record_data)
    if p_match:
        public_key = p_match.group(1)
        key_length = len(public_key) * 6
        if key_length < 1024:
            vulns.append({
                'type': 'WEAK_RSA_KEY',
                'severity': 'CRITICAL',
                'description': f'Potentially weak RSA key (~{key_length} bits)',
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
                'description': f'RSA key of {key_length} bits - below current standard',
                'solution': 'Upgrade to 2048-bit RSA key or higher',
                'attack_methods': [
                    'Computational attacks on RSA-1024',
                    'Future proofing attacks as computing power increases'
                ]
            })
    if 'v=DKIM1;' not in record_data:
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
    if 'k=rsa-sha1;' in record_data:
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
    print(f"   Solution: {vuln['solution']}")
    print(f"   Attack Methods:")
    for i, attack in enumerate(vuln['attack_methods'], 1):
        print(f"     {i}. {attack}")
    print()

def generate_attack_roadmap(spf_vulns, dmarc_vulns, dkim_vulns, mx_vulns, email_protections=None):
    print("\n" + "="*50)
    print("ATTACK ROADMAP")
    print("="*50)
    print()
    roadmap = []

    if email_protections:
        high_protection = any(p['bypass_difficulty'] == 'HIGH' for p in email_protections)
        if high_protection:
            roadmap.append("ENTERPRISE EMAIL SECURITY DETECTED - High difficulty bypass")
            roadmap.append("Attack vector: Focus on social engineering vs technical bypass")
        else:
            roadmap.append("BASIC/MEDIUM PROTECTION - Technical bypass possible")
            roadmap.append("Attack vector: Combine technical and social engineering")

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

    for i, step in enumerate(roadmap, 1):
        if i % 2 == 1:
            print_medium(step)
        else:
            print(f"   {step}")

def email_security_fullscan(domain, max_selectors=500):
    print("=" * 70)
    print(f"Starting Email Security Full Scan for: {domain}")
    print("=" * 70)
    total_vulnerabilities = 0
    vulnerability_breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    sources_breakdown = {'SPF': [], 'DMARC': [], 'DKIM': [], 'MX': []}

    dkim_vulns = []

    print("\n" + "="*50)
    print("DNS & INFRASTRUCTURE ANALYSIS")
    print("="*50)
    nameservers = get_nameservers(domain)
    mx_servers, mx_vulns = get_mx_servers(domain)
    total_vulnerabilities += len(mx_vulns)
    for vuln in mx_vulns:
        vulnerability_breakdown[vuln['severity']] += 1
        sources_breakdown['MX'].append(vuln['type'])

    print("\n" + "="*50)
    print("EMAIL SECURITY SERVICES DETECTION")
    print("="*50)
    email_protections = detect_protections(domain)

    print("\n" + "="*50)
    print("EMAIL AUTHENTICATION ANALYSIS")
    print("="*50)

    print("\n" + "-"*20)
    print("SPF SCAN RESULTS")
    print("-"*20)
    spf_vulns = spf_scan(domain)
    total_vulnerabilities += len(spf_vulns)
    if spf_vulns:
        for vuln in spf_vulns:
            print_vulnerability(vuln)
            vulnerability_breakdown[vuln['severity']] += 1
            sources_breakdown['SPF'].append(vuln['type'])
    else:
        print_good("No SPF vulnerabilities found")

    print("\n" + "-"*20)
    print("DMARC SCAN RESULTS")
    print("-"*20)
    dmarc_vulns = dmarc_scan(domain)
    total_vulnerabilities += len(dmarc_vulns)
    if dmarc_vulns:
        for vuln in dmarc_vulns:
            print_vulnerability(vuln)
            vulnerability_breakdown[vuln['severity']] += 1
            sources_breakdown['DMARC'].append(vuln['type'])
    else:
        print_good("No DMARC vulnerabilities found")

    print("\n" + "-"*20)
    print("DKIM SCAN RESULTS")
    print("-"*20)
    dkim_records = dkimscan(domain, max_selectors)
    if not dkim_records:
        print("No DKIM records found")
        print()
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
        print_vulnerability(no_dkim_vuln)
        total_vulnerabilities += 1
        vulnerability_breakdown['HIGH'] += 1
        sources_breakdown['DKIM'].append('NO_DKIM_RECORDS')
    else:
        print(f"Found {len(dkim_records)} DKIM records")
        print()
        dkim_vulns = []
        for dkim in dkim_records:
            record_vulns = dkimvulnscan(domain, dkim['selector'], dkim['data'])
            dkim_vulns.extend(record_vulns)
            total_vulnerabilities += len(record_vulns)
            if not record_vulns:
                print_good("   Secure configuration")
            else:
                for vuln in record_vulns:
                    print_vulnerability(vuln)
                    vulnerability_breakdown[vuln['severity']] += 1
                    sources_breakdown['DKIM'].append(vuln['type'])

    generate_attack_roadmap(spf_vulns, dmarc_vulns, dkim_vulns, mx_vulns, email_protections)

    print("\n" + "="*70)
    print("SCAN SUMMARY")
    print("="*70)
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

    print("\nSecurity Status: ", end="")
    if total_vulnerabilities == 0:
        print_good("EXCELLENT - No vulnerabilities detected")
    elif total_vulnerabilities <= 3 and vulnerability_breakdown['CRITICAL'] == 0:
        print_good("GOOD - Minor improvements needed")
    elif total_vulnerabilities <= 7 and vulnerability_breakdown['CRITICAL'] == 0:
        print_medium("FAIR - Several security issues to address")
    else:
        print_critical("POOR - Critical security issues present")

def main():
    parser = argparse.ArgumentParser(description='Email Security Scanner - Comprehensive analysis of SPF, DKIM, DMARC and MX configurations')
    parser.add_argument('-d', '--domain', type=str, help='Domain to scan (e.g., example.com)')

    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        sys.exit(1)

    email_security_fullscan(args.domain)

if __name__ == "__main__":
    main()
