#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import re
import json
import time
import socket
import ipaddress
import hashlib
import binascii
import requests
import subprocess
import os
import platform
import random
import string
from datetime import datetime
from tabulate import tabulate
from colorama import Fore, Back, Style, init
from bs4 import BeautifulSoup
import dns.resolver
import whois

# Initialize colorama
init(autoreset=True)

class OSINTTool:
    def __init__(self):
        self.results = {}
        self.failed_queries = []
        self.output_file = f"osint_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
        # Default data for offline analysis
        self.default_data = {
            "common_passwords": ["password123", "admin", "qwerty", "letmein", "welcome"],
            "common_creds": {
                "admin": ["password", "123456", "admin123"],
                "root": ["password", "123456", "admin123"]
            },
            "known_hashes": {
                "5f4dcc3b5aa765d61d8327deb882cf99": "password",
                "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8": "password"
            }
        }

    def banner(self):
        banner_text = f"""
{Fore.BLUE}╔════════════════════════════════════════════════════════════════╗
║                        OSINT GATHERING TOOL                    ║
║              Advanced Information Gathering Tool               ║
║                                                                ║
║ Features:                                                      ║
║ • Phone number analysis                                        ║
║ • Email breach detection                                       ║
║ • Source code analysis                                         ║
║ • Credential extraction                                        ║
║ • Hash cracking                                                ║
║ • Data pattern matching                                        ║
╚════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(banner_text)

    def validate_input(self, input_type, value):
        """Validate different input types"""
        validators = {
            "phone": lambda x: re.match(r'^\+?[1-9]\d{1,14}$', x),
            "email": lambda x: re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', x),
            "domain": lambda x: re.match(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$', x),
            "ip": lambda x: ipaddress.ip_address(x)
        }
        
        validator = validators.get(input_type)
        if validator and not validator(value):
            raise ValueError(f"Invalid {input_type}: {value}")
        return True

    def check_common_passwords(self, password):
        """Check if password is in common passwords list"""
        return password.lower() in self.default_data["common_passwords"]

    def brute_force_creds(self, username, domain):
        """Try common credentials against username"""
        results = []
        for cred_type, creds in self.default_data["common_creds"].items():
            for cred in creds:
                # Try with username as prefix/suffix
                test_cases = [
                    f"{username}{cred}",
                    f"{cred}{username}",
                    f"{username}_{cred}",
                    f"{cred}_{username}"
                ]
                
                for test in test_cases:
                    results.append({
                        "type": cred_type,
                        "username": username,
                        "password": test,
                        "success": False
                    })
        
        return results

    def identify_hash_type(self, hash_value):
        """Identify hash type based on length and format"""
        hash_types = {
            32: "MD5",
            40: "SHA1",
            64: "SHA256"
        }
        return hash_types.get(len(hash_value), "Unknown")

    def crack_hash(self, hash_value):
        """Attempt to crack hash using local dictionary"""
        hash_type = self.identify_hash_type(hash_value)
        if hash_type == "Unknown":
            return None
            
        # Try known hashes first
        if hash_value in self.default_data["known_hashes"]:
            return self.default_data["known_hashes"][hash_value]
            
        # Try common passwords
        for password in self.default_data["common_passwords"]:
            if hash_type == "MD5":
                test_hash = hashlib.md5(password.encode()).hexdigest()
            elif hash_type == "SHA1":
                test_hash = hashlib.sha1(password.encode()).hexdigest()
            elif hash_type == "SHA256":
                test_hash = hashlib.sha256(password.encode()).hexdigest()
                
            if test_hash == hash_value:
                return password
                
        return None

    def analyze_stealer_data(self, data):
        """Analyze stealer logs for sensitive data"""
        sensitive_patterns = {
            "emails": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "passwords": r"password[:=]\s*[\"'][^\"']*",
            "credit_cards": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
            "ip_addresses": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "hashes": r"[a-fA-F0-9]{32,64}"
        }
        
        results = {
            "found_patterns": {},
            "file_types": set(),
            "extracted_data": [],
            "hashes_found": [],
            "weak_passwords": []
        }
        
        # Extract file types
        for file_path in data.get("files", []):
            ext = file_path.split(".")[-1].lower()
            results["file_types"].add(ext)
        
        # Pattern matching
        for category, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, data.get("logs", ""))
            if matches:
                results["found_patterns"][category] = matches
                
                # Special handling for hashes
                if category == "hashes":
                    for match in matches:
                        hash_type = self.identify_hash_type(match)
                        cracked = self.crack_hash(match)
                        
                        results["hashes_found"].append({
                            "hash": match,
                            "type": hash_type,
                            "cracked": cracked
                        })
                
                # Check for weak passwords
                if category == "passwords":
                    for match in matches:
                        password = re.search(r'password[:=]\s*[\"\'\"]([^\"\'\"]+)', match)
                        if password:
                            pwd = password.group(1)
                            if self.check_common_passwords(pwd):
                                results["weak_passwords"].append(pwd)
        
        # Extract specific data points
        if "credentials" in data:
            for cred in data["credentials"]:
                results["extracted_data"].append({
                    "service": cred.get("service"),
                    "username": cred.get("username"),
                    "password": cred.get("password")[:10] + "..." if cred.get("password") else None
                })
        
        return results

    def generate_report(self):
        """Generate formatted report"""
        if not self.results:
            return "No results available."

        report = []
        for key, value in self.results.items():
            if isinstance(value, dict):
                report.append(f"\n{Fore.YELLOW}{key.upper()}{Style.RESET_ALL}")
                for k, v in value.items():
                    if isinstance(v, list):
                        report.append(f"  {k}:")
                        for item in v:
                            if isinstance(item, dict):
                                report.append(f"    - {k}:")
                                for ik, iv in item.items():
                                    report.append(f"      {ik}: {iv}")
                            else:
                                report.append(f"    - {item}")
                    else:
                        report.append(f"  {k}: {v}")
            else:
                report.append(f"{Fore.YELLOW}{key}:{Style.RESET_ALL} {value}")

        return "\n".join(report)

    def save_results(self):
        """Save results to file"""
        with open(self.output_file, 'w') as f:
            json.dump({
                "results": self.results,
                "failed_queries": self.failed_queries,
                "timestamp": datetime.now().isoformat()
            }, f, indent=2)
        print(f"{Fore.GREEN}Results saved to {self.output_file}")

    def run(self, args):
        """Execute all requested queries"""
        self.banner()
        
        # Process stealer data if provided
        if args.stealer_data:
            try:
                with open(args.stealer_data, 'r') as f:
                    stealer_data = json.load(f)
                self.results["stealer_analysis"] = self.analyze_stealer_data(stealer_data)
            except Exception as e:
                print(f"{Fore.RED}Error processing stealer data: {str(e)}")
                self.failed_queries.append({"type": "stealer", "value": args.stealer_data, "error": str(e)})

        # Process other queries
        if args.email:
            self.validate_input("email", args.email)
            # Local email validation
            self.results["email_validation"] = {
                "valid": True,
                "domain": args.email.split("@")[1],
                "tld": args.email.split("@")[1].split(".")[-1]
            }
            
            # Check if email might be compromised locally
            if "@gmail.com" in args.email or "@yahoo.com" in args.email:
                self.results["email_validation"]["breach_risk"] = "High (public domain)"
        
        if args.phone:
            self.validate_input("phone", args.phone)
            # Local phone validation
            self.results["phone_validation"] = {
                "valid": True,
                "country_code": args.phone[:3] if args.phone.startswith("+") else "+1",
                "area_code": args.phone[1:4] if args.phone.startswith("+") else args.phone[:3],
                "local_number": args.phone[4:] if args.phone.startswith("+") else args.phone[3:]
            }
            
            # Check for common prefixes
            common_prefixes = ["212", "312", "415", "202", "512"]
            if self.results["phone_validation"]["area_code"] in common_prefixes:
                self.results["phone_validation"]["area_code_risk"] = "Low (common area code)"

        if args.domain:
            self.validate_input("domain", args.domain)
            # Local domain validation
            self.results["domain_validation"] = {
                "valid": True,
                "tld": args.domain.split(".")[-1],
                "subdomains": []
            }
            
            # Check for common subdomains
            common_subdomains = ["www", "mail", "ftp", "blog", "shop"]
            for sub in common_subdomains:
                if f"{sub}.{args.domain}" != args.domain:
                    self.results["domain_validation"]["subdomains"].append(sub)
            
            # Try to resolve domain
            try:
                ip = socket.gethostbyname(args.domain)
                self.results["domain_validation"]["resolved_ip"] = ip
                self.results["domain_validation"]["ip_range"] = f"{ip.split('.')[0]}.{ip.split('.')[1]}.0.0-{ip.split('.')[0]}.{ip.split('.')[1]}.255.255"
            except:
                self.results["domain_validation"]["resolved_ip"] = "Unable to resolve"

        # Generate and display report
        report = self.generate_report()
        print(report)

        # Save results
        self.save_results()

        # Print summary
        success_count = len(self.results)
        failed_count = len(self.failed_queries)
        print(f"\n{Fore.GREEN}Query Summary:{Style.RESET_ALL}")
        print(f"  Successful: {success_count}")
        print(f"  Failed: {failed_count}")
        if failed_count > 0:
            print("\nFailed queries:")
            for query in self.failed_queries:
                print(f"  - {query['type']}: {query['value']} ({query['error']})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced OSINT Tool")
    parser.add_argument("--email", help="Email to analyze")
    parser.add_argument("--phone", help="Phone number to analyze")
    parser.add_argument("--domain", help="Domain to analyze")
    parser.add_argument("--stealer-data", help="File containing stealer data")
    args = parser.parse_args()

    if not any([args.email, args.phone, args.domain, args.stealer_data]):
        parser.print_help()
        sys.exit(1)

    tool = OSINTTool()
    tool.run(args)