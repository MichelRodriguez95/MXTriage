# MXTriage - Enterprise Email Security Assessment Suite

> **Professional Red Team Tool for Comprehensive MX, SPF, DKIM & DMARC Analysis**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Overview

MXTriage is a specialized Red Team toolkit for comprehensive email infrastructure assessment. Unlike generic DNS tools, MXTriage focuses on identifying exploitable vulnerabilities in enterprise email configurations for authorized penetration testing and security research.

## 🔍 Features

### 🔴 MX Infrastructure Analysis
- **MX Server Enumeration** - Discover and prioritize mail servers
- **Single Point of Failure Detection** - Identify lack of redundancy
- **Vulnerable Mail Server Detection** - Flag potentially exploitable services
- **Infrastructure Mapping** - Complete email delivery path analysis
- **Subdomain Takeover check** - Scan for Subdomain Takeover

### 🛡️ SPF Vulnerability Assessment
- **Policy Analysis** - Detect `+all`, `~all`, `?all` misconfigurations
- **Mechanism Auditing** - Identify broad `a/`mx` mechanisms
- **Include Chain Analysis** - Trace and audit SPF dependencies
- **IP Range Evaluation** - Flag overly permissive CIDR ranges
- **Subdomain SPF** - Check if subdomain have vulnerable SPF record
- **And Much More**

### 🔐 DKIM Security Audit
- **Selector Discovery** - 200+ built-in selectors with intelligent scanning
- **Cryptographic Analysis** - RSA key strength and algorithm validation
- **Configuration Testing** - Test mode detection and policy evaluation
- **Header Security** - Critical header signing verification
- **And Much More**

### 🛡️ DMARC Policy Evaluation
- **Policy Enforcement** - `none`/`quarantine`/`reject` analysis
- **Subdomain Protection** - SP policy gap detection
- **Reporting Configuration** - Missing aggregate/advisory reports
- **Alignment Verification** - Strict vs relaxed alignment checks
- **Subdomain DMARC** - Check if subdomain have vulnerable DMARC record
- **And Much More**

### 🎯 Enterprise Protection Detection
- **Service Identification** - Proofpoint, Mimecast, Microsoft Defender, etc.
- **Bypass Difficulty** - High/Medium/Low categorization
- **Attack Vector Mapping** - Service-specific evasion techniques

### 📊 Red Team Intelligence
- **Attack Roadmap** - Automated vulnerability prioritization
- **Exploitation Guidance** - Specific attack methods for each finding
- **Severity Scoring** - CRITICAL/HIGH/MEDIUM/LOW classification
- **Admit multiple domains** Scan multiple domains in a list with -l
- **JSON Result** - Save the result in a json to use it later with the other toos (-s option)
- **Professional Reporting** - Color-coded console output

## 🚨 Use Cases

- **Red Team Engagements** - Email infrastructure penetration testing
- **Security Assessments** - Proactive email security auditing
- **Bug Bounty Recon** - Quick identification of low-hanging fruit
- **Incident Response** - Forensic analysis of email attack vectors
- **Security Research** - Academic and professional email security studies

## ⚡ Quick Start

### Installation
```bash
git clone https://github.com/MichelRodriguez95/MXTriage.git
cd MXTriage
pip install -r requirements.txt
```

### Basic Usage
python mxanalyzer.py -d example.com

### 🛠️ Tool Suite Roadmap

#### ✅ Currently Available

    MXAnalyzer - Comprehensive email security assessment (mxanalyzer.py)

#### 🔄 In Development

    MXInject - MX injection vulnerability detection and validation

    MXExploit - Automated exploitation of identified email vulnerabilities

    MXReport - Professional reporting and executive summaries


#### ⚠️ Legal & Ethical Use

MXTriage is designed for:

    Authorized penetration testing

    Security research with proper permissions

    Educational purposes in controlled environments

⚠️ Warning: Unauthorized use against domains you don't own or have explicit permission to test is illegal and unethical.

#### 📜 License

This project is licensed under the MIT License.

#### 🙏 Acknowledgments

    Inspired by real-world Red Team operations

    Built with insights from email security research

    Community-driven selector database

## MXTriage - Because email is the #1 attack vector, and your Red Team should own it.



## 🎯 **TO DO LIST:**

### **MXInject (Detection Tool):**

## MXInject - MX Injection Vulnerability Scanner

### Core Features:
- [ ] Automated MX server discovery and prioritization
- [ ] SMTP connection testing without authentication
- [ ] Domain spoofing capability validation
- [ ] DMARC policy bypass detection
- [ ] Bulk domain processing capabilities
- [ ] False positive reduction mechanisms
- [ ] Service-specific injection techniques

### Advanced Features:
- [ ] TLS/STARTTLS support testing
- [ ] Rate limiting detection and evasion
- [ ] Geographic MX server mapping
- [ ] Historical MX record comparison
- [ ] Integration with MXAnalyzer findings

### Output:
- [ ] Vulnerability confidence scoring
- [ ] Exploitation difficulty assessment
- [ ] Proof-of-concept generation
- [ ] Integration with MXExploit

## MXExploit - Email Infrastructure Exploitation Framework

### Core Modules:
- [ ] Business Email Compromise (BEC) automation
- [ ] Credential phishing campaign generator
- [ ] Malware distribution simulation
- [ ] Internal reconnaissance via email
- [ ] Domain reputation impact assessment

### Attack Vectors:
- [ ] Direct MX injection with spoofed headers
- [ ] SPF policy bypass techniques
- [ ] DMARC policy exploitation
- [ ] Subdomain takeover chain attacks
- [ ] Attachment-based attack simulation

### Operational Security:
- [ ] Sender IP rotation and anonymization
- [ ] Email content randomization
- [ ] Timing-based evasion techniques
- [ ] Cleanup and artifact removal

### Reporting:
- [ ] Engagement metrics and success rates
- [ ] Client impact assessment
- [ ] Remediation guidance generation
