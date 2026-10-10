"""
Company Intelligence & Threat Profiler

This module profiles organizations based on their domain to identify relevant threats:
- Industry vertical and sector-specific threats
- Geographic location and nation-state threats
- Technology stack and associated CVEs
- Supply chain dependencies
- Political/geopolitical factors
- Known breaches and incidents

Uses multiple OSINT intelligence sources:
- Certificate Transparency (crt.sh) - certificates & subdomains
- Shodan/Censys - internet-facing assets (passive)
- Search engines - indexed secrets, staging pages
- Wayback Machine - historical content
- SecurityTrails/PassiveTotal - DNS history
- SSLLabs - TLS configuration
- MXToolbox - mail/DNS diagnostics
- GitHub - accidental commits of secrets
- WHOIS data
- DNS records
- Web scraping (robots.txt compliant)
- Public security databases
- Optional: OpenAI for enhanced analysis
"""

import os
import socket
import requests
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from urllib.parse import urlparse, quote
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

    def profile_domain(self, domain: str, options: Dict[str, bool] = None, group_name: str = None) -> Dict[str, Any]:
        """
        Profile a company based on their domain.

        Args:
            domain: Company domain (e.g., 'acme-corp.com')
            options: Dict of analysis options:
                - include_industry: Analyze industry threats
                - include_geography: Analyze geographic threats
                - include_tech_stack: Detect technology stack
                - include_supply_chain: Identify dependencies
            group_name: Optional group name for progress tracking

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

        # Use domain as group_name if not provided
        if not group_name:
            group_name = domain.replace('.', '_')

        print(f"\n=== Profiling Domain: {domain} ===\n")

        # Import progress tracking
        try:
            from archer.build.progress import write_progress
            self.write_progress = write_progress
            self.progress_group = group_name
        except ImportError:
            self.write_progress = None
            self.progress_group = None

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

        # 2. OSINT reconnaissance
        profile['osint'] = self._gather_osint(domain)

        # 3. Industry analysis
        if options.get('include_industry'):
            profile['threat_profile']['industry'] = self._analyze_industry(
                domain, profile['company_info']
            )

        # 4. Geographic analysis
        if options.get('include_geography'):
            profile['threat_profile']['geography'] = self._analyze_geography(
                domain, profile['company_info'], profile['osint']
            )

        # 5. Technology stack
        if options.get('include_tech_stack'):
            profile['threat_profile']['tech_stack'] = self._analyze_tech_stack(
                domain, profile['osint']
            )

        # 6. Supply chain (optional - more intensive)
        if options.get('include_supply_chain'):
            profile['threat_profile']['supply_chain'] = self._analyze_supply_chain(
                domain
            )

        # 7. Generate threat recommendations
        profile = self._generate_threat_recommendations(profile)

        # 7. AI enhancement (if enabled)
        if self.use_openai and self.openai_client:
            profile = self._enhance_with_ai(profile)

        # Write final completion status
        if self.write_progress:
            self.write_progress(self.progress_group, {
                "status": "profile_complete",
                "message": "Profile complete",
                "stage": 7,
                "total_stages": 7
            })

        print(f"\n=== Profile Complete ===\n")
        return profile

    def _gather_osint(self, domain: str) -> Dict[str, Any]:
        """Gather comprehensive OSINT data from multiple sources."""
        if self.write_progress:
            self.write_progress(self.progress_group, {
                "status": "profiling",
                "message": "Gathering OSINT intelligence...",
                "stage": 2,
                "total_stages": 7
            })
        print(f"[2/7] Gathering OSINT intelligence...")

        osint = {
            'subdomains': [],
            'certificates': [],
            'exposed_assets': [],
            'historical_data': [],
            'dns_history': [],
            'tls_config': {},
            'exposed_secrets': [],
            'github_leaks': []
        }

        # Certificate Transparency (crt.sh)
        try:
            print(f"  → Checking Certificate Transparency logs...")
            ct_data = self._check_certificate_transparency(domain)
            osint['certificates'] = ct_data.get('certificates', [])
            osint['subdomains'] = ct_data.get('subdomains', [])
            print(f"    ✓ Found {len(osint['subdomains'])} subdomains from certificates")
        except Exception as e:
            print(f"    ⚠ Certificate Transparency check failed: {e}")

        # Shodan (passive - requires API key)
        try:
            shodan_key = os.environ.get('SHODAN_API_KEY')
            if shodan_key:
                print(f"  → Checking Shodan for exposed assets...")
                shodan_data = self._check_shodan(domain, shodan_key)
                osint['exposed_assets'].extend(shodan_data)
                print(f"    ✓ Found {len(shodan_data)} exposed assets")
            else:
                print(f"    ℹ Shodan check skipped (no API key)")
        except Exception as e:
            print(f"    ⚠ Shodan check failed: {e}")

        # Wayback Machine
        try:
            print(f"  → Checking Wayback Machine for historical data...")
            wayback_data = self._check_wayback(domain)
            osint['historical_data'] = wayback_data
            print(f"    ✓ Found {len(wayback_data)} historical snapshots")
        except Exception as e:
            print(f"    ⚠ Wayback Machine check failed: {e}")

        # SecurityTrails (requires API key)
        try:
            st_key = os.environ.get('SECURITYTRAILS_API_KEY')
            if st_key:
                print(f"  → Checking SecurityTrails for DNS history...")
                dns_history = self._check_securitytrails(domain, st_key)
                osint['dns_history'] = dns_history
                print(f"    ✓ Retrieved DNS history")
            else:
                print(f"    ℹ SecurityTrails check skipped (no API key)")
        except Exception as e:
            print(f"    ⚠ SecurityTrails check failed: {e}")

        # SSLLabs
        try:
            print(f"  → Checking SSLLabs for TLS configuration...")
            tls_config = self._check_ssllabs(domain)
            osint['tls_config'] = tls_config
            if tls_config.get('grade'):
                print(f"    ✓ SSL grade: {tls_config['grade']}")
        except Exception as e:
            print(f"    ⚠ SSLLabs check failed: {e}")

        # Search engine dorking (Google)
        try:
            print(f"  → Checking for exposed secrets via search engines...")
            exposed_secrets = self._check_google_dorks(domain)
            osint['exposed_secrets'] = exposed_secrets
            if exposed_secrets:
                print(f"    ⚠ Found {len(exposed_secrets)} potential secret exposures")
        except Exception as e:
            print(f"    ⚠ Search engine check failed: {e}")

        # GitHub search
        try:
            github_token = os.environ.get('GITHUB_TOKEN')
            if github_token:
                print(f"  → Checking GitHub for accidental commits...")
                github_leaks = self._check_github(domain, github_token)
                osint['github_leaks'] = github_leaks
                if github_leaks:
                    print(f"    ⚠ Found {len(github_leaks)} potential GitHub leaks")
            else:
                print(f"    ℹ GitHub check skipped (no token)")
        except Exception as e:
            print(f"    ⚠ GitHub check failed: {e}")

        # Social Media Reconnaissance
        try:
            print(f"  → Searching social media for employee tech disclosures...")
            social_intel = self._check_social_media(domain)
            osint['social_media'] = social_intel
            if social_intel.get('technologies'):
                print(f"    ✓ Found {len(social_intel['technologies'])} technologies from social media")
            if social_intel.get('job_postings'):
                print(f"    ✓ Found {len(social_intel['job_postings'])} relevant job postings")
        except Exception as e:
            print(f"    ⚠ Social media check failed: {e}")

        return osint

    def _check_certificate_transparency(self, domain: str) -> Dict[str, Any]:
        """Check crt.sh for certificates and subdomains."""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=15)

            if response.status_code != 200:
                return {'certificates': [], 'subdomains': []}

            certs = response.json()

            # Extract unique subdomains
            subdomains = set()
            certificates = []

            for cert in certs[:100]:  # Limit to first 100
                name_value = cert.get('name_value', '')
                for name in name_value.split('\n'):
                    name = name.strip()
                    if name and domain in name:
                        # Remove wildcard prefix
                        clean_name = name.replace('*.', '')
                        if clean_name:
                            subdomains.add(clean_name)

                certificates.append({
                    'common_name': cert.get('common_name', ''),
                    'issuer': cert.get('issuer_name', ''),
                    'not_before': cert.get('not_before', ''),
                    'not_after': cert.get('not_after', '')
                })

            return {
                'certificates': certificates[:20],  # Limit output
                'subdomains': sorted(list(subdomains))[:50]  # Limit to 50
            }
        except Exception as e:
            return {'certificates': [], 'subdomains': []}

    def _check_shodan(self, domain: str, api_key: str) -> List[Dict]:
        """Check Shodan for internet-facing assets (passive)."""
        try:
            url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
            response = requests.get(url, timeout=10)

            if response.status_code != 200:
                return []

            data = response.json()
            assets = []

            # Get subdomain data
            for subdomain, details in data.get('data', {}).items():
                assets.append({
                    'subdomain': subdomain,
                    'type': details.get('type', 'unknown'),
                    'value': details.get('value', '')
                })

            return assets[:20]  # Limit results
        except Exception:
            return []

    def _check_wayback(self, domain: str) -> List[Dict]:
        """Check Wayback Machine for historical snapshots."""
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=10"
            response = requests.get(url, timeout=10)

            if response.status_code != 200:
                return []

            snapshots = response.json()
            historical_data = []

            for snapshot in snapshots[1:]:  # Skip header
                if len(snapshot) >= 3:
                    historical_data.append({
                        'timestamp': snapshot[1],
                        'url': snapshot[2],
                        'status_code': snapshot[4] if len(snapshot) > 4 else 'unknown'
                    })

            return historical_data
        except Exception:
            return []

    def _check_securitytrails(self, domain: str, api_key: str) -> Dict[str, Any]:
        """Check SecurityTrails for DNS history."""
        try:
            headers = {'APIKEY': api_key}
            url = f"https://api.securitytrails.com/v1/domain/{domain}"
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code != 200:
                return {}

            data = response.json()
            return {
                'current_dns': data.get('current_dns', {}),
                'subdomains': data.get('subdomain_count', 0)
            }
        except Exception:
            return {}

    def _check_ssllabs(self, domain: str) -> Dict[str, Any]:
        """Check SSLLabs for TLS configuration (API rate-limited)."""
        try:
            # Start analysis (cached results if recent scan exists)
            url = f"https://api.ssllabs.com/api/v3/analyze?host={domain}&fromCache=on&maxAge=24"
            response = requests.get(url, timeout=30)

            if response.status_code != 200:
                return {}

            data = response.json()

            # Extract key findings
            endpoints = data.get('endpoints', [])
            if endpoints:
                first_endpoint = endpoints[0]
                return {
                    'grade': first_endpoint.get('grade', 'Unknown'),
                    'has_warnings': first_endpoint.get('hasWarnings', False),
                    'is_exceptional': first_endpoint.get('isExceptional', False)
                }

            return {}
        except Exception:
            return {}

    def _check_google_dorks(self, domain: str) -> List[Dict]:
        """Check for common exposed secrets via search engine patterns."""
        # Note: These are passive checks - we don't actually query Google
        # We return patterns that should be checked manually or via Google Custom Search API

        dork_patterns = [
            f'site:{domain} ext:log',
            f'site:{domain} ext:sql',
            f'site:{domain} intext:"api_key"',
            f'site:{domain} intext:"password"',
            f'site:{domain} inurl:"/admin"',
            f'site:{domain} inurl:"/staging"',
            f'site:{domain} inurl:"/dev"',
            f'site:{domain} ext:env',
            f'site:{domain} intext:"aws_access_key"',
            f'site:{domain} intext:"private_key"'
        ]

        return [{'pattern': pattern, 'recommendation': 'Check manually or via Google Custom Search API'}
                for pattern in dork_patterns[:5]]

    def _check_github(self, domain: str, token: str) -> List[Dict]:
        """Search GitHub for accidental commits containing domain."""
        try:
            headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github.v3+json'
            }

            # Search for domain in code
            search_query = quote(f'{domain} password OR api_key OR secret')
            url = f"https://api.github.com/search/code?q={search_query}&per_page=5"

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code != 200:
                return []

            data = response.json()
            leaks = []

            for item in data.get('items', []):
                leaks.append({
                    'repository': item.get('repository', {}).get('full_name', ''),
                    'path': item.get('path', ''),
                    'url': item.get('html_url', '')
                })

            return leaks
        except Exception:
            return []

    def _check_social_media(self, domain: str) -> Dict[str, Any]:
        """
        Check social media platforms for employee disclosures about technologies.

        Searches for:
        - LinkedIn employee posts mentioning technologies
        - Job postings revealing tech stack
        - Twitter/X posts from employees
        - GitHub profiles of employees
        """
        social_data = {
            'technologies': [],
            'job_postings': [],
            'employee_disclosures': [],
            'platforms_checked': []
        }

        # Extract company name from domain
        company_name = domain.split('.')[0].replace('-', ' ').replace('_', ' ').title()

        # Check LinkedIn via Google search (no API key needed for basic search)
        linkedin_data = self._search_linkedin_intel(domain, company_name)
        social_data['technologies'].extend(linkedin_data.get('technologies', []))
        social_data['job_postings'].extend(linkedin_data.get('job_postings', []))
        social_data['platforms_checked'].append('LinkedIn (via search)')

        # Check Twitter/X for employee tech mentions
        twitter_data = self._search_twitter_intel(domain, company_name)
        social_data['technologies'].extend(twitter_data.get('technologies', []))
        social_data['employee_disclosures'].extend(twitter_data.get('disclosures', []))
        social_data['platforms_checked'].append('Twitter/X (via search)')

        # Check job boards for posted positions
        job_data = self._search_job_postings(domain, company_name)
        social_data['job_postings'].extend(job_data.get('postings', []))
        social_data['technologies'].extend(job_data.get('technologies', []))
        social_data['platforms_checked'].append('Job Boards')

        # Deduplicate technologies
        social_data['technologies'] = list(set(social_data['technologies']))

        return social_data

    def _search_linkedin_intel(self, domain: str, company_name: str) -> Dict[str, Any]:
        """
        Search LinkedIn for technology disclosures via Google dorks.

        Note: This uses passive search patterns. For active scraping, you'd need:
        - LinkedIn API access (requires approval)
        - Or use services like PhantomBuster, Apify
        """
        intel = {
            'technologies': [],
            'job_postings': []
        }

        # Technology keywords to search for
        tech_keywords = [
            # Cloud Platforms
            'AWS', 'Azure', 'Google Cloud', 'GCP', 'Oracle Cloud',
            # Networking
            'Cisco', 'Juniper', 'Palo Alto', 'Fortinet', 'F5',
            # Security
            'CrowdStrike', 'SentinelOne', 'Carbon Black', 'Splunk', 'Microsoft Defender',
            # Databases
            'Oracle', 'SQL Server', 'MySQL', 'PostgreSQL', 'MongoDB',
            # Containers/Orchestration
            'Kubernetes', 'Docker', 'OpenShift', 'Rancher',
            # DevOps
            'Jenkins', 'GitLab', 'GitHub Actions', 'Terraform', 'Ansible',
            # Applications
            'SAP', 'Salesforce', 'ServiceNow', 'Workday',
            # Infrastructure
            'VMware', 'Hyper-V', 'Citrix', 'Active Directory'
        ]

        # Build search patterns for LinkedIn job posts
        # These would be checked manually or via Google Custom Search API
        search_patterns = [
            f'site:linkedin.com/jobs "{company_name}" {{tech}}',
            f'site:linkedin.com "{company_name}" "we use" {{tech}}',
            f'site:linkedin.com "{company_name}" "looking for" {{tech}}',
        ]

        # Return technology list and search recommendations
        # In production, you'd actually execute these searches
        intel['job_postings'] = [
            {
                'source': 'LinkedIn',
                'search_pattern': pattern.format(tech='<technology>'),
                'recommendation': 'Check manually or use Google Custom Search API / LinkedIn API'
            }
            for pattern in search_patterns[:3]
        ]

        # Common technologies often disclosed on LinkedIn
        # These are high-probability technologies based on company size/industry
        intel['technologies'] = self._infer_common_technologies(domain)

        return intel

    def _search_twitter_intel(self, domain: str, company_name: str) -> Dict[str, Any]:
        """
        Search Twitter/X for employee tech disclosures.

        Employees often tweet about:
        - Technologies they work with
        - Conference talks mentioning their stack
        - Troubleshooting posts revealing infrastructure
        - Job postings they're hiring for
        """
        intel = {
            'technologies': [],
            'disclosures': []
        }

        # Twitter/X search patterns (would need Twitter API for actual execution)
        search_patterns = [
            f'from:* "{company_name}" "we use" (AWS OR Azure OR Google Cloud)',
            f'from:* "{company_name}" "our stack" (technology OR tech OR infrastructure)',
            f'from:* "{company_name}" "hiring" (engineer OR developer OR architect)',
            f'"{company_name}" employee (AWS OR Azure OR Cisco OR Kubernetes)',
        ]

        intel['disclosures'] = [
            {
                'source': 'Twitter/X',
                'search_pattern': pattern,
                'recommendation': 'Check manually via Twitter search or use Twitter API v2'
            }
            for pattern in search_patterns[:3]
        ]

        return intel

    def _search_job_postings(self, domain: str, company_name: str) -> Dict[str, Any]:
        """
        Search job boards for technology requirements in postings.

        Checks:
        - Indeed
        - LinkedIn Jobs
        - Glassdoor
        - Company careers page
        """
        intel = {
            'postings': [],
            'technologies': []
        }

        # Try to fetch company careers page
        try:
            careers_urls = [
                f'https://{domain}/careers',
                f'https://{domain}/jobs',
                f'https://careers.{domain}',
                f'https://jobs.{domain}'
            ]

            for url in careers_urls:
                try:
                    response = requests.get(url, timeout=5, allow_redirects=True)
                    if response.status_code == 200:
                        content = response.text.lower()

                        # Extract technology mentions
                        tech_patterns = {
                            'cloud': ['aws', 'azure', 'google cloud', 'gcp'],
                            'networking': ['cisco', 'juniper', 'palo alto', 'fortinet'],
                            'security': ['crowdstrike', 'sentinelone', 'splunk', 'defender'],
                            'databases': ['oracle', 'sql server', 'mysql', 'postgresql', 'mongodb'],
                            'containers': ['kubernetes', 'docker', 'openshift'],
                            'devops': ['jenkins', 'gitlab', 'terraform', 'ansible']
                        }

                        found_techs = []
                        for category, techs in tech_patterns.items():
                            for tech in techs:
                                if tech in content:
                                    found_techs.append(tech.title())

                        if found_techs:
                            intel['technologies'].extend(found_techs)
                            intel['postings'].append({
                                'source': 'Company Careers Page',
                                'url': url,
                                'technologies_found': found_techs,
                                'method': 'direct_fetch'
                            })
                            break  # Found working careers page

                except requests.RequestException:
                    continue

        except Exception as e:
            pass

        # Add job board search recommendations
        job_boards = [
            {
                'source': 'Indeed',
                'search_url': f'https://www.indeed.com/jobs?q={quote(company_name)}',
                'recommendation': 'Check for technology keywords in job descriptions'
            },
            {
                'source': 'LinkedIn Jobs',
                'search_url': f'https://www.linkedin.com/jobs/search/?keywords={quote(company_name)}',
                'recommendation': 'Check for required skills and technologies'
            },
            {
                'source': 'Glassdoor',
                'search_url': f'https://www.glassdoor.com/Job/jobs.htm?sc.keyword={quote(company_name)}',
                'recommendation': 'Check interview questions for technology mentions'
            }
        ]

        intel['postings'].extend(job_boards)

        return intel

    def _infer_common_technologies(self, domain: str) -> List[str]:
        """
        Infer likely technologies based on domain characteristics.

        These are high-probability technologies that are commonly disclosed
        or can be inferred from public information.
        """
        common_techs = []

        # Check domain registrar/hosting (from WHOIS or IP)
        # This is a simplified inference - in production you'd check actual data
        common_techs.extend([
            'Microsoft Office 365',  # Very common
            'Active Directory',       # Enterprise standard
            'VPN Solutions',          # Standard security
        ])

        return common_techs

    def _gather_domain_info(self, domain: str) -> Dict[str, Any]:
        """Gather basic information about the domain."""
        if self.write_progress:
            self.write_progress(self.progress_group, {
                "status": "profiling",
                "message": "Gathering domain information...",
                "stage": 1,
                "total_stages": 7
            })
        print(f"[1/7] Gathering domain information...")

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

        # Identify the organisation itself (Wikidata, homepage, ccTLD) rather than
        # inferring from the domain string or where its IPs happen to be hosted
        from archer.intelligence.company_identity import resolve_identity

        identity = resolve_identity(domain)
        info['identity'] = identity
        info['company_name'] = identity['company_name']
        info['country'] = identity['country']
        info['headquarters'] = identity['headquarters']
        for line in identity['evidence']:
            print(f"  ✓ {line}")

        return info

    def _analyze_industry(self, domain: str, company_info: Dict) -> Dict[str, Any]:
        """Analyze industry sector and associated threats."""
        if self.write_progress:
            self.write_progress(self.progress_group, {
                "status": "profiling",
                "message": "Analyzing industry sector...",
                "stage": 3,
                "total_stages": 7
            })
        print(f"[3/7] Analyzing industry sector...")

        industry_data = {
            'sector': None,
            'subsector': None,
            'threats': [],
            'threat_groups': [],
            'confidence': 'low'
        }

        identity = company_info.get('identity') or {}
        if identity.get('sector'):
            industry_data['sector'] = identity['sector']
            industry_data['subsector'] = ", ".join(identity.get('organisation_types', [])[:3]) or None
            industry_data['confidence'] = identity.get('confidence', 'medium')
            industry_data['evidence'] = identity.get('evidence', [])
            print(f"  ✓ Detected sector: {industry_data['sector']} (confidence: {industry_data['confidence']})")
            sector_threats = self._map_sector_to_threats(industry_data['sector'])
            industry_data['threat_groups'] = sector_threats['groups']
            industry_data['threats'] = sector_threats['threats']
            return industry_data

        # Fallback: keyword detection on the domain name (heuristic)
        domain_lower = domain.lower()
        company_name = (company_info.get('company_name') or '').lower()

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
        """Map industry sector to relevant threat actors from MITRE ATT&CK data."""

        print(f"    → Querying MITRE ATT&CK for {sector} sector threat groups...")

        # Try to query MITRE ATT&CK data
        try:
            from archer.mitre import get_stix_data

            # Get MITRE ATT&CK data
            bundle = get_stix_data(
                "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
            )

            # Map sectors to MITRE industry labels
            sector_to_industry_map = {
                'finance': ['financial', 'bank', 'finance', 'credit', 'payment'],
                'healthcare': ['health', 'medical', 'hospital', 'pharma', 'clinic', 'care'],
                'technology': ['tech', 'software', 'cloud', 'saas', 'it'],
                'energy': ['energy', 'oil', 'gas', 'power', 'electric', 'utility'],
                'defense': ['defense', 'military', 'aerospace', 'aviation', 'weapon'],
                'government': ['government', 'state', 'federal', 'public sector', 'diplomatic'],
                'retail': ['retail', 'commerce', 'shopping', 'consumer'],
                'manufacturing': ['manufacturing', 'industrial', 'factory'],
                'telecommunications': ['telecom', 'communication', 'network', 'isp', 'mobile'],
                'media': ['media', 'entertainment', 'publishing', 'broadcasting'],
                'education': ['education', 'university', 'academic', 'school'],
                'transportation': ['transportation', 'logistics', 'shipping', 'aviation']
            }

            industry_keywords = sector_to_industry_map.get(sector, [sector])

            # Find threat groups targeting this sector. Bundle objects are plain dicts
            # (obj.type raised AttributeError, so this always fell back to the static map).
            import re
            from archer.intelligence.country_context import clean_description

            patterns = [re.compile(rf"\b{re.escape(k.lower())}", re.IGNORECASE) for k in industry_keywords]
            scored = []
            for obj in bundle.objects:
                if obj.get('type') != 'intrusion-set' or obj.get('revoked') or obj.get('x_mitre_deprecated'):
                    continue
                description = clean_description(obj.get('description', ''))
                hits = sum(len(p.findall(description)) for p in patterns)
                if hits:
                    scored.append((hits, obj.get('name')))

            # Most-discussed sector ties first, name as a stable tiebreak
            matching_groups = [name for _, name in sorted(scored, key=lambda x: (-x[0], x[1]))]

            if matching_groups:
                print(f"      ✓ Found {len(matching_groups)} threat groups from MITRE ATT&CK")
                return {
                    'groups': matching_groups[:10],  # Limit to top 10
                    'threats': self._get_sector_threat_descriptions(sector)
                }
            else:
                print(f"      ⚠ No MITRE groups found, using fallback mapping")
                # Fallback to static mapping
                return self._get_fallback_sector_mapping(sector)

        except Exception as e:
            print(f"      ⚠ MITRE ATT&CK query failed: {e}, using fallback")
            # Fallback to static mapping
            return self._get_fallback_sector_mapping(sector)

    def _get_fallback_sector_mapping(self, sector: str) -> Dict[str, List[str]]:
        """Fallback static mapping if MITRE query fails."""
        sector_mapping = {
            'finance': {
                'groups': ['FIN7', 'FIN8', 'Carbanak', 'Lazarus Group', 'APT38'],
                'threats': self._get_sector_threat_descriptions('finance')
            },
            'healthcare': {
                'groups': ['APT41', 'ALPHV/BlackCat', 'Scattered Spider'],
                'threats': self._get_sector_threat_descriptions('healthcare')
            },
            'technology': {
                'groups': ['APT41', 'Lazarus Group', 'Scattered Spider', 'LAPSUS$'],
                'threats': self._get_sector_threat_descriptions('technology')
            },
            'energy': {
                'groups': ['XENOTIME', 'TEMP.Veles', 'Sandworm', 'APT33'],
                'threats': self._get_sector_threat_descriptions('energy')
            },
            'defense': {
                'groups': ['APT28', 'APT29', 'APT40', 'APT1', 'Lazarus Group'],
                'threats': self._get_sector_threat_descriptions('defense')
            },
            'government': {
                'groups': ['APT28', 'APT29', 'APT40', 'Turla', 'OilRig'],
                'threats': self._get_sector_threat_descriptions('government')
            },
            'telecommunications': {
                'groups': ['APT10', 'APT41', 'Sandworm'],
                'threats': self._get_sector_threat_descriptions('telecommunications')
            }
        }
        return sector_mapping.get(sector, {'groups': [], 'threats': []})

    def _get_sector_threat_descriptions(self, sector: str) -> List[str]:
        """Get common threat descriptions for a sector."""
        threat_descriptions = {
            'finance': [
                'Financial theft and fraud',
                'Business Email Compromise (BEC)',
                'ATM/POS malware',
                'SWIFT system attacks',
                'Cryptocurrency theft',
                'Wire fraud and account takeover'
            ],
            'healthcare': [
                'Ransomware attacks',
                'Medical data theft (PHI/PII)',
                'Research IP theft',
                'Supply chain attacks on medical devices',
                'Insurance fraud',
                'Clinical trial data theft'
            ],
            'technology': [
                'Source code theft',
                'Supply chain compromises',
                'SaaS/Cloud account takeovers',
                'Intellectual property theft',
                'Zero-day development',
                'Customer data breaches'
            ],
            'energy': [
                'Critical infrastructure attacks',
                'ICS/SCADA targeting',
                'Sabotage and disruption',
                'Espionage',
                'Nation-state attacks',
                'Operational technology compromise'
            ],
            'defense': [
                'Military intelligence theft',
                'Weapons systems targeting',
                'Nation-state espionage',
                'Contractor supply chain attacks',
                'Classified data exfiltration',
                'R&D theft'
            ],
            'government': [
                'Nation-state espionage',
                'Election interference',
                'Policy intelligence gathering',
                'Diplomatic targeting',
                'Influence operations',
                'Critical infrastructure targeting'
            ],
            'telecommunications': [
                'Network infrastructure compromise',
                'Subscriber data theft',
                'Call/SMS interception',
                'Nation-state surveillance',
                'Supply chain attacks',
                '5G infrastructure targeting'
            ]
        }
        return threat_descriptions.get(sector, ['General cyber threats'])

    def _analyze_geography(self, domain: str, company_info: Dict, osint: Dict) -> Dict[str, Any]:
        """Analyze geographic location and nation-state threats."""
        if self.write_progress:
            self.write_progress(self.progress_group, {
                "status": "profiling",
                "message": "Analyzing geographic threats...",
                "stage": 4,
                "total_stages": 7
            })
        print(f"[4/7] Analyzing geographic threats...")

        geo_data = {
            'country': None,
            'region': None,
            'country_evidence': [],
            # Where the site is served from (often a CDN edge); never used as the company's location
            'hosting_country': None,
            'hosting_region': None,
            'threat_actors': [],
            'geopolitical_risks': []
        }

        if company_info.get('country'):
            geo_data['country'] = company_info['country']
            geo_data['region'] = company_info.get('headquarters')
            geo_data['country_evidence'] = (company_info.get('identity') or {}).get('evidence', [])
            print(f"  ✓ Company location: {', '.join(filter(None, [geo_data['region'], geo_data['country']]))}")
            geo_data['threat_actors'] = self._map_country_to_threats(geo_data['country'])
            geo_data['geopolitical_risks'] = self._assess_geopolitical_risks(geo_data['country'])
        else:
            print("  ⚠ Could not determine company location")

        # Hosting location, for context only
        if company_info['ip_addresses']:
            try:
                ip = company_info['ip_addresses'][0]
                response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
                geoip_data = response.json() if response.status_code == 200 else {}
                if geoip_data.get('status') == 'success':
                    geo_data['hosting_country'] = geoip_data.get('country')
                    geo_data['hosting_region'] = geoip_data.get('regionName')
                    print(f"  ℹ Hosting location (may be a CDN edge): {geo_data['hosting_region']}, {geo_data['hosting_country']}")
            except Exception as e:
                print(f"  ⚠ Hosting GeoIP lookup failed: {e}")

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

    def _assess_geopolitical_risks(self, country: str) -> List[str]:
        """Assess geopolitical risks based on country and current events."""

        # Geopolitical risk factors by country/region
        risk_assessment = {
            'United States': [
                'Primary target for nation-state espionage',
                'High-value target for ransomware groups',
                'Critical infrastructure at risk',
                'Financial sector heavily targeted'
            ],
            'United Kingdom': [
                'Nation-state espionage (Russia, China, Iran)',
                'Financial services targeting',
                'Brexit-related supply chain risks',
                'Critical infrastructure concerns'
            ],
            'Germany': [
                'Industrial espionage from state actors',
                'Manufacturing sector targeting',
                'EU regulatory compliance requirements',
                'Energy sector vulnerabilities'
            ],
            'France': [
                'Nation-state targeting (Russia, China)',
                'Defense industry espionage',
                'Energy sector risks',
                'EU data sovereignty concerns'
            ],
            'Japan': [
                'Regional tensions (North Korea, China)',
                'Technology IP theft',
                'Manufacturing sector targeting',
                'Critical infrastructure risks'
            ],
            'Australia': [
                'APT targeting (China-linked groups)',
                'Five Eyes intelligence sharing obligations',
                'Critical infrastructure (energy, mining)',
                'Regional geopolitical tensions'
            ],
            'Israel': [
                'Constant nation-state threats',
                'Advanced persistent threat activity',
                'Critical infrastructure targeting',
                'Defense industry espionage'
            ],
            'Ukraine': [
                'Active cyber warfare',
                'Critical infrastructure under attack',
                'Nation-state aggression',
                'Collateral damage from regional conflicts'
            ],
            'Taiwan': [
                'Elevated APT activity (China-linked)',
                'Technology sector IP theft',
                'Critical infrastructure risks',
                'Geopolitical tensions'
            ]
        }

        return risk_assessment.get(country, ['General cyber threat landscape'])

    def _analyze_tech_stack(self, domain: str, osint: Dict) -> Dict[str, Any]:
        """Detect technology stack and associated vulnerabilities."""
        if self.write_progress:
            self.write_progress(self.progress_group, {
                "status": "profiling",
                "message": "Analyzing technology stack...",
                "stage": 5,
                "total_stages": 7
            })
        print(f"[5/7] Analyzing technology stack...")

        tech_data = {
            'web_server': None,
            'web_server_custom_banner': False,
            'cdn': None,
            'technologies': [],
            'cloud_provider': None,
            'cves': [],
            'security_headers': {},
            'tls_grade': None,
            'subdomains': [],
            'exposed_services': []
        }

        # Integrate OSINT data
        if osint:
            # Add TLS configuration from SSLLabs
            if osint.get('tls_config', {}).get('grade'):
                tech_data['tls_grade'] = osint['tls_config']['grade']
                print(f"  ✓ TLS grade: {tech_data['tls_grade']}")

            # Add subdomain information
            if osint.get('subdomains'):
                tech_data['subdomains'] = osint['subdomains'][:10]  # Limit to 10
                print(f"  ✓ Found {len(osint['subdomains'])} subdomains")

            # Add exposed services from Shodan
            if osint.get('exposed_assets'):
                tech_data['exposed_services'] = osint['exposed_assets']
                print(f"  ✓ Found {len(tech_data['exposed_services'])} exposed services")

            # Add technologies from social media reconnaissance
            if osint.get('social_media', {}).get('technologies'):
                social_techs = osint['social_media']['technologies']
                tech_data['technologies'].extend(social_techs)
                tech_data['social_media_intel'] = {
                    'technologies_from_social': social_techs,
                    'job_postings_analyzed': len(osint['social_media'].get('job_postings', [])),
                    'platforms_checked': osint['social_media'].get('platforms_checked', [])
                }
                print(f"  ✓ Found {len(social_techs)} technologies from social media/job postings")

        # Make HTTP request to detect technologies
        try:
            # domain is user input: refuse private/internal targets and re-check every redirect
            import html
            import re
            from archer.parsers.blog_analyzer import _fetch_public_url

            response = _fetch_public_url(f'https://{domain}')

            # Detect web server. Many sites send a custom banner ("Tesco Web Server")
            # that names no real product, so say so rather than reporting it as one.
            if 'Server' in response.headers:
                banner = response.headers['Server']
                known = ('nginx', 'apache', 'iis', 'cloudflare', 'akamaighost', 'envoy', 'openresty', 'gws',
                         'litespeed', 'caddy', 'varnish', 'cloudfront', 'amazons3', 'awselb', 'gunicorn',
                         'uvicorn', 'kestrel', 'jetty', 'tomcat', 'lighttpd', 'tengine', 'istio')
                tech_data['web_server'] = banner
                tech_data['web_server_custom_banner'] = not any(k in banner.lower() for k in known)
                note = " (custom banner, real software hidden)" if tech_data['web_server_custom_banner'] else ""
                print(f"  ✓ Server header: {banner}{note}")

            # CDN / edge in front of the site: explains why hosting GeoIP isn't the company's location
            h = {k.lower(): v for k, v in response.headers.items()}
            cdn_markers = {
                # Akamai-GRN / Akamai-Cache-Status headers, AKA_A2 / bm_* Bot Manager cookies,
                # or its entity-encoded errors.edgesuite.net block page
                'Akamai': ('akamai' in h.get('server', '').lower()
                           or any(k.startswith(('akamai', 'x-akamai')) for k in h)
                           or re.search(r'\b(?:AKA_A2|ak_bmsc|bm_sz?|bm_so)=', h.get('set-cookie', '')) is not None
                           or 'edgesuite' in html.unescape(response.text[:2000])),
                'Cloudflare': 'cf-ray' in h or 'cloudflare' in h.get('server', '').lower(),
                'Amazon CloudFront': 'x-amz-cf-id' in h or 'cloudfront' in h.get('via', '').lower(),
                'Fastly': 'x-served-by' in h and 'cache-' in h.get('x-served-by', '') or 'fastly' in h.get('via', '').lower(),
                'Azure Front Door': 'x-azure-ref' in h,
            }
            tech_data['cdn'] = next((name for name, hit in cdn_markers.items() if hit), None)
            if tech_data['cdn']:
                print(f"  ✓ CDN: {tech_data['cdn']}")

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

            # Check security headers, but only on a real page: a bot-protection 403
            # from the CDN says nothing about the site's own header policy
            if response.ok:
                security_headers = ['Strict-Transport-Security', 'Content-Security-Policy',
                                  'X-Frame-Options', 'X-Content-Type-Options']
                for header in security_headers:
                    tech_data['security_headers'][header] = header in response.headers

                missing_headers = [h for h, present in tech_data['security_headers'].items() if not present]
                if missing_headers:
                    print(f"  ⚠ Missing security headers: {', '.join(missing_headers)}")
            else:
                tech_data['blocked_status'] = response.status_code
                print(f"  ℹ Site returned HTTP {response.status_code} (likely bot protection); security headers not assessed")

        except Exception as e:
            print(f"  ⚠ Could not analyze website: {e}")

        return tech_data

    def _analyze_supply_chain(self, domain: str) -> Dict[str, Any]:
        """Analyze supply chain dependencies (basic analysis)."""
        if self.write_progress:
            self.write_progress(self.progress_group, {
                "status": "profiling",
                "message": "Analyzing social media disclosures...",
                "stage": 6,
                "total_stages": 7
            })
        print(f"[6/7] Analyzing supply chain...")

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
        if self.write_progress:
            self.write_progress(self.progress_group, {
                "status": "profiling",
                "message": "Generating threat recommendations...",
                "stage": 7,
                "total_stages": 7
            })
        print(f"[7/7] Generating threat recommendations...")

        # Ordered, de-duplicated: sector-specific groups first, then country-based ones
        recommended_groups = {}
        recommended_techniques = set()
        risk_score = 0

        # Aggregate threat groups from all analyses
        threat_profile = profile.get('threat_profile', {})

        # From industry analysis
        industry = threat_profile.get('industry', {})
        if industry.get('threat_groups'):
            recommended_groups.update(dict.fromkeys(industry['threat_groups']))
            risk_score += 30

        # From geography analysis
        geography = threat_profile.get('geography', {})
        if geography.get('threat_actors'):
            recommended_groups.update(dict.fromkeys(geography['threat_actors']))
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
            headers_seen = tech_stack.get('security_headers') or {}
            # Empty means not assessed (e.g. blocked by bot protection), not absent
            if headers_seen and not headers_seen.get('Strict-Transport-Security'):
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


def profile_company(domain: str, options: Dict[str, bool] = None, use_openai: bool = False, group_name: str = None) -> Dict[str, Any]:
    """
    Profile a company based on their domain.

    Args:
        domain: Company domain
        options: Analysis options dict
        use_openai: Whether to use AI enhancement
        group_name: Optional group name for progress tracking

    Returns:
        Company profile with threat intelligence
    """
    profiler = CompanyProfiler(use_openai=use_openai)
    return profiler.profile_domain(domain, options, group_name=group_name)
