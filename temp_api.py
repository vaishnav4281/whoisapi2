import whois
import requests
import json
import socket
from datetime import datetime
from dateutil.relativedelta import relativedelta

class DomainInfoAPI:
    def __init__(self):
        self.api_key = "853fb4da0616e5de34f54a8cbfe39f8735b2eafde6060eed87a16c0c268ba1fe11e43e937c215508"
        self.risk_check_url = "https://api.abuseipdb.com/api/v2/check"
        self.base_url = "https://api.ipify.org"

    def get_domain_info(self, domain):
        """Get domain information"""
        try:
            print(f"Attempting domain info lookup for {domain}...")
            
            # Get WHOIS info
            whois_info = self.get_whois_info(domain)
            
            # Get IP address
            ip = self.get_ip_address(domain)
            
            # Get abuse score
            abuse_info = self.get_abuse_score(ip) if ip else None
            
            # Get IP info
            ip_info = self.get_ip_info(ip) if ip else None
            
            # Return raw data
            return {
                'domain': domain,
                'ip': ip,
                'abuse_score': abuse_info.get('data', {}).get('abuseConfidenceScore') if abuse_info else None,
                'ip_info': ip_info,
                'whois_info': whois_info
            }
        except Exception as e:
            import traceback
            print(f"Error in domain info lookup for {domain}: {str(e)}")
            print(f"Full traceback:\n{traceback.format_exc()}")
            return None

    def get_whois_info(self, domain):
        """Get WHOIS information for a domain"""
        try:
            print(f"Attempting WHOIS lookup for {domain}...")
            
            try:
                # Use whois library with timeout
                w = whois.whois(domain, timeout=10)
                print(f"WHOIS response received for {domain}")
                
                if not w:
                    print(f"WHOIS returned empty response for {domain}")
                    return None
                    
                # Extract WHOIS information
                whois_data = {
                    'domain_name': w.domain_name if hasattr(w, 'domain_name') else None,
                    'creation_date': w.creation_date if hasattr(w, 'creation_date') else None,
                    'expiration_date': w.expiration_date if hasattr(w, 'expiration_date') else None,
                    'registrar': w.registrar if hasattr(w, 'registrar') else None,
                    'status': w.status if hasattr(w, 'status') else None,
                    'dnssec': w.dnssec if hasattr(w, 'dnssec') else None,
                    'name_servers': w.name_servers if hasattr(w, 'name_servers') else None,
                    'updated_date': w.updated_date if hasattr(w, 'updated_date') else None,
                    'country': w.country if hasattr(w, 'country') else None,
                    'state': w.state if hasattr(w, 'state') else None,
                    'city': w.city if hasattr(w, 'city') else None,
                    'address': w.address if hasattr(w, 'address') else None,
                    'org': w.org if hasattr(w, 'org') else None,
                    'registrant_name': w.registrant_name if hasattr(w, 'registrant_name') else None,
                    'registrant_organization': w.registrant_organization if hasattr(w, 'registrant_organization') else None,
                    'registrant_email': w.registrant_email if hasattr(w, 'registrant_email') else None,
                    'admin_name': w.admin_name if hasattr(w, 'admin_name') else None,
                    'admin_email': w.admin_email if hasattr(w, 'admin_email') else None,
                    'tech_name': w.tech_name if hasattr(w, 'tech_name') else None,
                    'tech_email': w.tech_email if hasattr(w, 'tech_email') else None,
                    'registrant_phone': w.registrant_phone if hasattr(w, 'registrant_phone') else None,
                    'admin_phone': w.admin_phone if hasattr(w, 'admin_phone') else None,
                    'tech_phone': w.tech_phone if hasattr(w, 'tech_phone') else None
                }
                
                # Format dates if they exist
                if whois_data['creation_date']:
                    whois_data['creation_date'] = whois_data['creation_date'].isoformat()
                if whois_data['expiration_date']:
                    whois_data['expiration_date'] = whois_data['expiration_date'].isoformat()
                if whois_data['updated_date']:
                    whois_data['updated_date'] = whois_data['updated_date'].isoformat()
                
                print(f"Successfully got WHOIS info for {domain}")
                return whois_data
                
            except Exception as whois_error:
                print(f"WHOIS lookup failed: {str(whois_error)}")
                return None
                
        except Exception as e:
            import traceback
            print(f"Error in WHOIS lookup for {domain}: {str(e)}")
            print(f"Full traceback:\n{traceback.format_exc()}")
            return None

    def get_ip_address(self, domain):
        """Get IP address for a domain"""
        try:
            print(f"Attempting IP lookup for {domain}...")
            
            # Try using ip-api.com first
            try:
                print("Trying ip-api.com lookup...")
                response = requests.get(f"http://ip-api.com/json/{domain}", timeout=5)
                response.raise_for_status()
                data = response.json()
                if data.get('status') == 'success':
                    print(f"Successfully got IP from ip-api.com: {data.get('query')}")
                    return data.get('query')
                else:
                    print(f"ip-api.com lookup failed: {data.get('message', 'Unknown error')}")
            except Exception as ip_api_error:
                print(f"ip-api.com lookup failed: {str(ip_api_error)}")
                
            # Try DNS lookup as fallback
            try:
                print("Trying DNS lookup...")
                ip = socket.gethostbyname(domain)
                print(f"Successfully got IP from DNS: {ip}")
                return ip
            except socket.gaierror as dns_error:
                print(f"DNS lookup failed: {str(dns_error)}")
                return None
                
        except Exception as e:
            import traceback
            print(f"Error in IP lookup for {domain}: {str(e)}")
            print(f"Full traceback:\n{traceback.format_exc()}")
            return None

    def get_abuse_score(self, ip):
        """Get abuse score from AbuseIPDB"""
        try:
            print(f"Getting abuse score for IP: {ip}...")
            
            headers = {
                'Key': self.api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90
            }
            
            response = requests.get(
                self.risk_check_url,
                headers=headers,
                params=params,
                timeout=10
            )
            
            response.raise_for_status()
            data = response.json()
            print(f"Successfully got abuse score for {ip}")
            return data
            
        except Exception as e:
            import traceback
            print(f"Error getting abuse score for {ip}: {str(e)}")
            print(f"Full traceback:\n{traceback.format_exc()}")
            return None

    def get_ip_info(self, ip):
        """Get IP information from ip-api.com"""
        try:
            print(f"Getting IP info for {ip}...")
            
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=5
            )
            
            response.raise_for_status()
            data = response.json()
            print(f"Successfully got IP info for {ip}")
            return data
            
        except Exception as e:
            import traceback
            print(f"Error getting IP info for {ip}: {str(e)}")
            print(f"Full traceback:\n{traceback.format_exc()}")
            return None

    def format_age(self, creation_date):
        """Format domain age in years, months, and days"""
        try:
            if not creation_date:
                return "Unknown"
            
            now = datetime.now()
            age = relativedelta(now, creation_date)
            return f"{age.years} years, {age.months} months, {age.days} days"
            
        except Exception as e:
            import traceback
            print(f"Error formatting age: {str(e)}")
            print(f"Full traceback:\n{traceback.format_exc()}")
            return "Unknown"

# Example usage
def main():
    api = DomainInfoAPI()
    domain = "github.com"
    info = api.get_domain_info(domain)
    print(json.dumps(info, indent=2))

if __name__ == "__main__":
    main()
