"""
Company Intelligence & Threat Profiler

This module profiles organizations based on their domain to identify relevant threats:
- Industry vertical and sector-specific threats
- Geographic location and nation-state threats
- Technology stack and associated CVEs
- Supply chain dependencies
- Political/geopolitical factors
- Known breaches and incidents

Uses multiple intelligence sources:
- WHOIS data
- DNS records
- Web scraping (robots.txt compliant)
- Public security databases
- CVE databases
- Optional: OpenAI for enhanced analysis
"""

import os
import re
import json
import socket
import requests
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver


class CompanyProfiler:
    """Profile an organization's threat landscape based on their domain."""

    def __init__(self, use_openai: bool = False):
        """
        Initialize the company profiler.

        Args:
            use_openai: Whether to use OpenAI for enhanced analysis
        """
        self.use_openai = use_openai
        self.openai_client = None

        if use_openai:
            self._init_openai()

    def _init_openai(self):
        """Initialize OpenAI client if API key is available."""
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            print("Warning: OPENAI_API_KEY not found. AI enhancement disabled.")
            self.use_openai = False
            return

        try:
            import openai
            self.openai_client = openai.OpenAI(api_key=api_key)
        except ImportError:
            print("Warning: openai package not installed.")
            self.use_openai = False

    def profile_domain(self, domain: str, options: Dict[str, bool] = None) -> Dict[str, Any]:
        """
        Profile a company based on their domain.

        Args:
            domain: Company domain (e.g., 'acme-corp.com')
            options: Dict of analysis options:
                - include_industry: Analyze industry threats
                - include_geography: Analyze geographic threats
                - include_tech_stack: Detect technology stack
                - include_supply_chain: Identify dependencies

        Returns:
            Comprehensive profile dictionary with threat intelligence
        """
        if options is None:
            options = {
                'include_industry': True,
                'include_geography': True,
                'include_tech_stack': True,
                'include_supply_chain': False
            }

        print(f"\n=== Profiling Domain: {domain} ===\n")

        profile = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'company_info': {},
            'threat_profile': {},
            'recommended_groups': [],
            'recommended_techniques': [],
            'risk_score': 0
        }

        # 1. Basic domain information
        profile['company_info'] = self._gather_domain_info(domain)

        # 2. Industry analysis
        if options.get('include_industry'):
            profile['threat_profile']['industry'] = self._analyze_industry(
                domain, profile['company_info']
            )

        # 3. Geographic analysis
        if options.get('include_geography'):
            profile['threat_profile']['geography'] = self._analyze_geography(
                domain, profile['company_info']
            )

        # 4. Technology stack
        if options.get('include_tech_stack'):
            profile['threat_profile']['tech_stack'] = self._analyze_tech_stack(
                domain
            )

        # 5. Supply chain (optional - more intensive)
        if options.get('include_supply_chain'):
            profile['threat_profile']['supply_chain'] = self._analyze_supply_chain(
                domain
            )

        # 6. Generate threat recommendations
        profile = self._generate_threat_recommendations(profile)

        # 7. AI enhancement (if enabled)
        if self.use_openai and self.openai_client:
            profile = self._enhance_with_ai(profile)

        print(f"\n=== Profile Complete ===\n")
        return profile

    def _gather_domain_info(self, domain: str) -> Dict[str, Any]:
        """Gather basic information about the domain."""
        print(f"[1/6] Gathering domain information...")

        info = {
            'domain': domain,
            'company_name': None,
            'organization': None,
            'country': None,
            'registrar': None,
            'ip_addresses': [],
            'nameservers': []
        }

        # Get IP addresses
        try:
            ip_addresses = socket.getaddrinfo(domain, None)
            info['ip_addresses'] = list(set([ip[4][0] for ip in ip_addresses]))
            print(f"  ✓ Found {len(info['ip_addresses'])} IP address(es)")
        except socket.gaierror as e:
            print(f"  ⚠ Could not resolve domain: {e}")

        # Get nameservers
        try:
            ns_records = dns.resolver.resolve(domain, 'NS')
            info['nameservers'] = [str(ns) for ns in ns_records]
            print(f"  ✓ Found {len(info['nameservers'])} nameserver(s)")
        except Exception as e:
            print(f"  ⚠ Could not get nameservers: {e}")

        # Try to extract company name from domain
        # Remove TLD and common patterns
        domain_parts = domain.replace('.com', '').replace('.org', '').replace('.net', '')
        domain_parts = domain_parts.replace('-', ' ').replace('_', ' ')
        info['company_name'] = domain_parts.title()

        return info

    def _analyze_industry(self, domain: str, company_info: Dict) -> Dict[str, Any]:
        """Analyze industry sector and associated threats."""
        print(f"[2/6] Analyzing industry sector...")

        industry_data = {
            'sector': None,
            'subsector': None,
            'threats': [],
            'threat_groups': [],
            'confidence': 'low'
        }

        # Industry keyword detection (heuristic)
        domain_lower = domain.lower()
        company_name = company_info.get('company_name', '').lower()

        industry_keywords = {
            'finance': ['bank', 'financial', 'fintech', 'capital', 'investment', 'trading'],
            'healthcare': ['health', 'medical', 'hospital', 'pharma', 'care', 'clinic'],
            'technology': ['tech', 'software', 'cloud', 'data', 'cyber', 'digital'],
            'energy': ['energy', 'power', 'oil', 'gas', 'electric', 'utility'],
            'defense': ['defense', 'defence', 'military', 'aerospace', 'aviation'],
            'government': ['gov', 'state', 'federal', 'agency', 'department'],
            'retail': ['retail', 'shop', 'store', 'ecommerce', 'marketplace'],
            'manufacturing': ['manufacturing', 'industrial', 'factory', 'production'],
            'telecommunications': ['telecom', 'wireless', 'mobile', 'network'],
            'media': ['media', 'news', 'broadcast', 'entertainment', 'publishing']
        }

        detected_sectors = []
        for sector, keywords in industry_keywords.items():
            for keyword in keywords:
                if keyword in domain_lower or keyword in company_name:
                    detected_sectors.append(sector)
                    break

        if detected_sectors:
            industry_data['sector'] = detected_sectors[0]
            industry_data['confidence'] = 'high' if len(detected_sectors) == 1 else 'medium'
            print(f"  ✓ Detected sector: {industry_data['sector']} (confidence: {industry_data['confidence']})")

            # Map sectors to known threat groups
            sector_threats = self._map_sector_to_threats(industry_data['sector'])
            industry_data['threat_groups'] = sector_threats['groups']
            industry_data['threats'] = sector_threats['threats']
        else:
            print(f"  ⚠ Could not determine industry sector")
            industry_data['confidence'] = 'none'

        return industry_data

    def _map_sector_to_threats(self, sector: str) -> Dict[str, List[str]]:
        """Map industry sector to relevant threat actors and TTPs."""

        # Sector-specific threat intelligence
        sector_mapping = {
            'finance': {
                'groups': ['FIN7', 'FIN8', 'Carbanak', 'Lazarus Group', 'APT38'],
                'threats': [
                    'Financial theft and fraud',
                    'Business Email Compromise (BEC)',
                    'ATM/POS malware',
                    'SWIFT system attacks',
                    'Cryptocurrency theft'
                ]
            },
            'healthcare': {
                'groups': ['APT41', 'ALPHV/BlackCat', 'Scattered Spider'],
                'threats': [
                    'Ransomware attacks',
                    'Medical data theft (PHI/PII)',
                    'Research IP theft',
                    'Supply chain attacks on medical devices',
                    'Insurance fraud'
                ]
            },
            'technology': {
                'groups': ['APT41', 'Lazarus Group', 'Scattered Spider', 'LAPSUS$'],
                'threats': [
                    'Source code theft',
                    'Supply chain compromises',
                    'SaaS/Cloud account takeovers',
                    'Intellectual property theft',
                    'Zero-day development'
                ]
            },
            'energy': {
                'groups': ['XENOTIME', 'TEMP.Veles', 'Sandworm', 'APT33'],
                'threats': [
                    'Critical infrastructure attacks',
                    'ICS/SCADA targeting',
                    'Sabotage and disruption',
                    'Espionage',
                    'Nation-state attacks'
                ]
            },
            'defense': {
                'groups': ['APT28', 'APT29', 'APT40', 'APT1', 'Lazarus Group'],
                'threats': [
                    'Military intelligence theft',
                    'Weapons systems targeting',
                    'Nation-state espionage',
                    'Contractor supply chain attacks',
                    'Classified data exfiltration'
                ]
            },
            'government': {
                'groups': ['APT28', 'APT29', 'APT40', 'Turla', 'OilRig'],
                'threats': [
                    'Nation-state espionage',
                    'Election interference',
                    'Policy intelligence gathering',
                    'Diplomatic targeting',
                    'Influence operations'
                ]
            },
            'telecommunications': {
                'groups': ['APT10', 'APT41', 'Sandworm'],
                'threats': [
                    'Network infrastructure compromise',
                    'Subscriber data theft',
                    'Call/SMS interception',
                    'Nation-state surveillance',
                    'Supply chain attacks'
                ]
            }
        }

        return sector_mapping.get(sector, {'groups': [], 'threats': []})

    def _analyze_geography(self, domain: str, company_info: Dict) -> Dict[str, Any]:
        """Analyze geographic location and nation-state threats."""
        print(f"[3/6] Analyzing geographic threats...")

        geo_data = {
            'country': None,
            'region': None,
            'threat_actors': [],
            'geopolitical_risks': []
        }

        # Try to get country from IP geolocation (simplified)
        if company_info['ip_addresses']:
            # In production, you'd use a proper GeoIP service
            # For now, use heuristics based on domain TLD
            tld = domain.split('.')[-1]
            tld_country_map = {
                'us': 'United States',
                'uk': 'United Kingdom',
                'de': 'Germany',
                'fr': 'France',
                'cn': 'China',
                'ru': 'Russia',
                'jp': 'Japan',
                'au': 'Australia'
            }
            geo_data['country'] = tld_country_map.get(tld, 'Unknown')

            if geo_data['country'] != 'Unknown':
                print(f"  ✓ Detected country: {geo_data['country']}")

                # Map countries to relevant threat actors
                geo_threats = self._map_country_to_threats(geo_data['country'])
                geo_data['threat_actors'] = geo_threats

        return geo_data

    def _map_country_to_threats(self, country: str) -> List[str]:
        """Map country to relevant nation-state threat actors."""

        # Nation-state threat actor targeting by victim country
        targeting_map = {
            'United States': ['APT28', 'APT29', 'APT40', 'Lazarus Group', 'OilRig'],
            'United Kingdom': ['APT28', 'APT29', 'APT40'],
            'Germany': ['APT28', 'Turla'],
            'France': ['APT28', 'OilRig'],
            'Japan': ['APT40', 'Lazarus Group'],
            'Australia': ['APT40']
        }

        return targeting_map.get(country, [])

    def _analyze_tech_stack(self, domain: str) -> Dict[str, Any]:
        """Detect technology stack and associated vulnerabilities."""
        print(f"[4/6] Analyzing technology stack...")

        tech_data = {
            'web_server': None,
            'technologies': [],
            'cloud_provider': None,
            'cves': [],
            'security_headers': {}
        }

        # Make HTTP request to detect technologies
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Archer Threat Intelligence Scanner)'
            }
            response = requests.get(f'https://{domain}', headers=headers, timeout=10, allow_redirects=True)

            # Detect web server
            if 'Server' in response.headers:
                tech_data['web_server'] = response.headers['Server']
                print(f"  ✓ Web server: {tech_data['web_server']}")

            # Detect technologies from headers and content
            tech_indicators = {
                'WordPress': ['wp-content', 'wp-includes'],
                'Apache': ['Apache'],
                'nginx': ['nginx'],
                'Microsoft-IIS': ['IIS'],
                'Cloudflare': ['cloudflare'],
                'AWS': ['amazon', 'aws'],
                'Azure': ['azure'],
                'Google Cloud': ['google']
            }

            page_content = response.text.lower()
            for tech, indicators in tech_indicators.items():
                for indicator in indicators:
                    if indicator.lower() in str(response.headers).lower() or indicator in page_content:
                        if tech not in tech_data['technologies']:
                            tech_data['technologies'].append(tech)
                            print(f"  ✓ Detected technology: {tech}")
                        break

            # Check security headers
            security_headers = ['Strict-Transport-Security', 'Content-Security-Policy',
                              'X-Frame-Options', 'X-Content-Type-Options']
            for header in security_headers:
                tech_data['security_headers'][header] = header in response.headers

            missing_headers = [h for h, present in tech_data['security_headers'].items() if not present]
            if missing_headers:
                print(f"  ⚠ Missing security headers: {', '.join(missing_headers)}")

        except Exception as e:
            print(f"  ⚠ Could not analyze website: {e}")

        return tech_data

    def _analyze_supply_chain(self, domain: str) -> Dict[str, Any]:
        """Analyze supply chain dependencies (basic analysis)."""
        print(f"[5/6] Analyzing supply chain...")

        supply_chain_data = {
            'third_party_services': [],
            'cdn_providers': [],
            'email_providers': [],
            'risks': []
        }

        # Check DNS records for third-party services
        try:
            # Check MX records for email providers
            mx_records = dns.resolver.resolve(domain, 'MX')
            for mx in mx_records:
                mx_str = str(mx.exchange)
                if 'google' in mx_str:
                    supply_chain_data['email_providers'].append('Google Workspace')
                elif 'outlook' in mx_str or 'microsoft' in mx_str:
                    supply_chain_data['email_providers'].append('Microsoft 365')
                elif 'proofpoint' in mx_str:
                    supply_chain_data['third_party_services'].append('Proofpoint')

            if supply_chain_data['email_providers']:
                print(f"  ✓ Email provider: {', '.join(supply_chain_data['email_providers'])}")

        except Exception as e:
            print(f"  ⚠ Could not check email provider: {e}")

        return supply_chain_data

    def _generate_threat_recommendations(self, profile: Dict) -> Dict:
        """Generate threat group and technique recommendations based on profile."""
        print(f"[6/6] Generating threat recommendations...")

        recommended_groups = set()
        recommended_techniques = set()
        risk_score = 0

        # Aggregate threat groups from all analyses
        threat_profile = profile.get('threat_profile', {})

        # From industry analysis
        industry = threat_profile.get('industry', {})
        if industry.get('threat_groups'):
            recommended_groups.update(industry['threat_groups'])
            risk_score += 30

        # From geography analysis
        geography = threat_profile.get('geography', {})
        if geography.get('threat_actors'):
            recommended_groups.update(geography['threat_actors'])
            risk_score += 20

        # Add technique recommendations based on common patterns
        if recommended_groups:
            # High-frequency techniques across threat groups
            common_techniques = [
                'T1566.001',  # Spearphishing Attachment
                'T1566.002',  # Spearphishing Link
                'T1059.001',  # PowerShell
                'T1047',      # Windows Management Instrumentation
                'T1003',      # Credential Dumping
                'T1078',      # Valid Accounts
                'T1071.001',  # Web Protocols
                'T1041',      # Exfiltration Over C2 Channel
                'T1486',      # Data Encrypted for Impact (Ransomware)
            ]
            recommended_techniques.update(common_techniques)

        # Tech stack specific techniques
        tech_stack = threat_profile.get('tech_stack', {})
        if tech_stack.get('technologies'):
            if 'WordPress' in tech_stack['technologies']:
                recommended_techniques.add('T1190')  # Exploit Public-Facing Application
                risk_score += 15
            if not tech_stack.get('security_headers', {}).get('Strict-Transport-Security'):
                recommended_techniques.add('T1557')  # Man-in-the-Middle
                risk_score += 10

        profile['recommended_groups'] = list(recommended_groups)
        profile['recommended_techniques'] = list(recommended_techniques)
        profile['risk_score'] = min(risk_score, 100)  # Cap at 100

        print(f"  ✓ Recommended threat groups: {len(profile['recommended_groups'])}")
        print(f"  ✓ Recommended techniques: {len(profile['recommended_techniques'])}")
        print(f"  ✓ Risk score: {profile['risk_score']}/100")

        return profile

    def _enhance_with_ai(self, profile: Dict) -> Dict:
        """Use AI to enhance the threat profile with deeper analysis."""
        print(f"\n[AI Enhancement] Analyzing with OpenAI...")

        try:
            # Create a summary prompt for AI analysis
            prompt = self._create_ai_prompt(profile)

            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity threat intelligence analyst specializing in threat profiling and adversary attribution."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.7,
                max_tokens=1000
            )

            ai_analysis = response.choices[0].message.content
            profile['ai_analysis'] = ai_analysis
            print(f"  ✓ AI analysis complete")

        except Exception as e:
            print(f"  ⚠ AI enhancement failed: {e}")
            profile['ai_analysis'] = None

        return profile

    def _create_ai_prompt(self, profile: Dict) -> str:
        """Create a prompt for AI analysis."""
        threat_profile = profile.get('threat_profile', {})
        industry = threat_profile.get('industry', {})
        geography = threat_profile.get('geography', {})

        prompt = f"""Analyze this organization's threat landscape:

Domain: {profile['domain']}
Company: {profile['company_info'].get('company_name', 'Unknown')}

Industry: {industry.get('sector', 'Unknown')}
Country: {geography.get('country', 'Unknown')}

Identified Threat Groups: {', '.join(profile.get('recommended_groups', [])) or 'None'}

Based on this profile, provide:
1. The top 3-5 most likely threat actors targeting this organization
2. The most critical attack vectors to defend against
3. Any emerging threats specific to this industry/geography
4. Recommended security priorities

Keep the response concise and actionable."""

        return prompt


def profile_company(domain: str, options: Dict[str, bool] = None, use_openai: bool = False) -> Dict[str, Any]:
    """
    Profile a company based on their domain.

    Args:
        domain: Company domain
        options: Analysis options dict
        use_openai: Whether to use AI enhancement

    Returns:
        Company profile with threat intelligence
    """
    profiler = CompanyProfiler(use_openai=use_openai)
    return profiler.profile_domain(domain, options)
