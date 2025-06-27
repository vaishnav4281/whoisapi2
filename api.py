import whois
import requests
import json
import socket
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta
from dateutil.parser import parse as parse_date
import concurrent.futures
import os
from dotenv import load_dotenv

load_dotenv()

class DomainInfoAPI:
    def __init__(self):
        self.whoisxml_api_key = os.getenv("WHOISXML_API_KEY")
        self.abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")
        self.whoisxmlapi_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
        self.risk_check_url = "https://api.abuseipdb.com/api/v2/check"
        self.base_url = "https://api.ipify.org"

    def get_domain_info(self, domain):
        """
        Aggregates domain WHOIS, IP, and abuse information.
        Ensures all expected fields are present in the final output,
        even if some lookups fail.
        """
        try:
            # Initialize final_info with default values for clarity and consistency
            final_info = {
                'domain': domain,
                'creation_date': 'Unknown',
                'expiry_date': 'Unknown',
                'age': 'Unknown',
                'registrar': 'Unknown',
                'domain_status': 'Unknown',
                'registrant_name': 'Unknown',
                'registrant_email': 'Unknown',
                'registrant_phone': 'Unknown',
                'ip_address': None,
                'abuse_score': None,
                'country': 'Unknown', # From IP info
                'city': 'Unknown',    # From IP info
                'status': 'error', # Overall status, will be updated
                'error': None # Overall error message
            }

            # Get WHOIS information using WhoisXMLAPI
            whois_result = self.get_whois_info(domain)
            final_info.update(whois_result) # This will populate all WHOIS fields and initial status/error

            # Get IP Address (independent of WHOIS success)
            ip = self.get_ip_address(domain)
            final_info['ip_address'] = ip

            # Get Abuse Score (depends on IP)
            if ip:
                abuse_score_data = self.get_abuse_score(ip)
                if abuse_score_data and abuse_score_data.get('status') == 'success' and 'data' in abuse_score_data:
                    final_info['abuse_score'] = abuse_score_data['data'].get('abuseConfidenceScore')
                elif abuse_score_data and abuse_score_data.get('error'):
                    # Append abuse score error to overall error
                    final_info['error'] = f"{final_info['error']}; AbuseIPDB error: {abuse_score_data['error']}" if final_info['error'] else f"AbuseIPDB error: {abuse_score_data['error']}"

            # Get IP Geolocation Information (depends on IP)
            if ip:
                ip_geo_info = self.get_ip_info(ip)
                # Explicitly map IP fields to avoid overwriting WHOIS fields
                final_info['country'] = ip_geo_info.get('country', 'Unknown')
                final_info['city'] = ip_geo_info.get('city', 'Unknown')
                final_info['as'] = ip_geo_info.get('as')
                final_info['countryCode'] = ip_geo_info.get('countryCode')
                final_info['isp'] = ip_geo_info.get('isp')
                final_info['lat'] = ip_geo_info.get('lat')
                final_info['lon'] = ip_geo_info.get('lon')
                final_info['org'] = ip_geo_info.get('org')
                final_info['query'] = ip_geo_info.get('query')
                final_info['region'] = ip_geo_info.get('region')
                final_info['regionName'] = ip_geo_info.get('regionName')
                final_info['timezone'] = ip_geo_info.get('timezone')
                final_info['zip'] = ip_geo_info.get('zip')

                if ip_geo_info.get('status') == 'fail' and ip_geo_info.get('message'):
                    # Append IP geo error to overall error
                    final_info['error'] = f"{final_info['error']}; IP geo lookup error: {ip_geo_info['message']}" if final_info['error'] else f"IP geo lookup error: {ip_geo_info['message']}"

            # Determine Overall Status
            # If WHOIS lookup was successful AND IP address was found, then overall status is success.
            # Otherwise, it's an error.
            if final_info.get('status') == 'success' and final_info.get('ip_address') is not None:
                final_info['status'] = 'success'
                final_info['error'] = None # Clear error if everything is successful
            else:
                final_info['status'] = 'error'
                # If there's no specific error message yet, provide a generic one
                if not final_info['error']:
                    final_info['error'] = "Could not retrieve complete domain information."

            return final_info
        except Exception as e:
            import traceback
            print(f"Error getting domain info: {str(e)}")
            print(f"Full traceback:\n{traceback.format_exc()}")
            # Return a consistent error structure for unexpected errors
            return {
                'domain': domain, 'creation_date': 'Unknown', 'expiry_date': 'Unknown',
                'age': 'Unknown', 'registrar': 'Unknown', 'domain_status': 'Unknown',
                'registrant_name': 'Unknown', 'registrant_email': 'Unknown',
                'registrant_phone': 'Unknown', 'ip_address': None,
                'abuse_score': None, 'country': 'Unknown', 'city': 'Unknown',
                'status': 'error',
                'error': f'An unexpected error occurred in get_domain_info: {str(e)}'
            }

    def _get_default_whois_info_dict(self, domain, error_message=None):
        """Returns a dictionary with default/empty WHOIS fields."""
        return {
            'domain': domain,
            'creation_date': 'Unknown',
            'expiry_date': 'Unknown',
            'age': 'Unknown',
            'registrar': 'Unknown',
            'domain_status': 'Unknown',
            'registrant_name': 'Unknown',
            'registrant_email': 'Unknown',
            'registrant_phone': 'Unknown',
            'status': 'error',
            'error': error_message
        }

    def get_whois_info(self, domain):
        """Get WHOIS information for a domain using WhoisXMLAPI, with a fallback to python-whois."""
        try:
            socket.gethostbyname(domain)
        except socket.gaierror:
            print(f"Domain {domain} does not resolve")
            return self._get_default_whois_info_dict(domain, 'Domain does not resolve')

        # 1. Try WhoisXMLAPI first if a key is provided
        if self.whoisxml_api_key:
            print(f"Attempting WHOIS lookup for {domain} via WhoisXMLAPI...")
            params = {
                'apiKey': self.whoisxml_api_key,
                'domainName': domain,
                'outputFormat': 'JSON'
            }
            try:
                response = requests.get(self.whoisxmlapi_url, params=params, timeout=10)
                response.raise_for_status()
                data = response.json()

                if 'ErrorMessage' in data:
                    # API returned a structured error, treat as failure for fallback
                    raise ValueError(f"API Error: {data['ErrorMessage'].get('msg', 'Unknown error')}")

                record = data.get('WhoisRecord', {})
                if not record:
                    raise ValueError("No WHOIS record found in API response")

                # If we get here, the API call was successful. Parse and return.
                return self._parse_whoisxmlapi_record(domain, record)

            except (requests.exceptions.RequestException, json.JSONDecodeError, ValueError) as e:
                print(f"WhoisXMLAPI failed for {domain}: {e}. Attempting fallback.")
                # Fall through to the fallback method below

        # 2. Fallback to python-whois
        return self._get_whois_info_fallback(domain)

    def _parse_whoisxmlapi_record(self, domain, record):
        """Parses a successful WhoisRecord from WhoisXMLAPI."""
        creation_date_str = record.get('createdDate', 'Unknown')
        expiry_date_str = record.get('expiresDate', 'Unknown')

        creation_date, expiry_date = None, None
        try:
            if creation_date_str != 'Unknown': creation_date = parse_date(creation_date_str)
            if expiry_date_str != 'Unknown': expiry_date = parse_date(expiry_date_str)
        except (ValueError, TypeError) as e:
            print(f"Could not parse date from WhoisXMLAPI: {e}")

        age_str = "Unknown"
        if creation_date:
            age = relativedelta(datetime.now(timezone.utc), creation_date)
            age_str = f"{age.years} years, {age.months} months, {age.days} days"

        registrant_contact = record.get('registrant', {})
        domain_status = record.get('status', 'Unknown')
        if isinstance(domain_status, list):
            domain_status = ", ".join(domain_status)

        return {
            'domain': domain,
            'creation_date': creation_date.isoformat() if creation_date else 'Unknown',
            'expiry_date': expiry_date.isoformat() if expiry_date else 'Unknown',
            'age': age_str,
            'registrar': record.get('registrarName', 'Unknown'),
            'domain_status': domain_status,
            'registrant_name': registrant_contact.get('name', 'Unknown'),
            'registrant_email': registrant_contact.get('email', 'Unknown'),
            'registrant_phone': registrant_contact.get('telephone', 'Unknown'),
            'status': 'success',
            'error': None
        }

    def _get_whois_info_fallback(self, domain):
        """Fallback to get WHOIS information using the python-whois library."""
        print(f"Falling back to python-whois for {domain}...")
        try:
            w = whois.whois(domain)

            if not w or not w.domain_name:
                return self._get_default_whois_info_dict(domain, 'No WHOIS record found (fallback)')

            creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            expiry_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date

            age_str = "Unknown"
            if creation_date:
                # Make creation_date timezone-aware if it's naive
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=timezone.utc)
                age = relativedelta(datetime.now(timezone.utc), creation_date)  # Both are now timezone-aware
                age_str = f"{age.years} years, {age.months} months, {age.days} days"

            domain_status = w.status
            if isinstance(domain_status, list):
                domain_status = ", ".join(domain_status)

            return {
                'domain': domain,
                'creation_date': creation_date.isoformat() if creation_date else 'Unknown',
                'expiry_date': expiry_date.isoformat() if expiry_date else 'Unknown',
                'age': age_str,
                'registrar': w.registrar or 'Unknown',
                'domain_status': domain_status or 'Unknown',
                'registrant_name': w.name or 'Unknown',
                'registrant_email': (w.email[0] if isinstance(w.email, list) else w.email) or 'Unknown',
                'registrant_phone': w.registrant_phone or 'Unknown',
                'status': 'success_fallback',
                'error': None
            }
        except Exception as e:
            print(f"python-whois fallback failed for {domain}: {e}")
            return self._get_default_whois_info_dict(domain, f'WHOIS fallback failed: {e}')

    def get_ip_address(self, domain):
        """Get IP address for a domain"""
        try:
            print(f"Attempting IP lookup for {domain}...")
            # Try DNS lookup first
            try:
                ip = socket.gethostbyname(domain)
                print(f"Successfully got IP from DNS: {ip}")
                return ip
            except socket.gaierror as dns_error:
                print(f"DNS lookup failed for {domain}: {str(dns_error)}")
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
                'Key': self.abuseipdb_api_key,
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
            return {
                'status': 'fail',
                'error': f'AbuseIPDB lookup failed: {str(e)}',
                'data': {'abuseConfidenceScore': None} # Ensure data structure is consistent
            }

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
            return {
                'status': 'fail',
                'message': f'IP geolocation lookup failed: {str(e)}',
                # Provide default/empty values for other expected keys from ip-api.com
                'country': 'Unknown', 'city': 'Unknown', 'as': None, 'countryCode': None,
                'isp': None, 'lat': None, 'lon': None, 'org': None, 'query': ip,
                'region': None, 'regionName': None, 'timezone': None, 'zip': None
            }


# Example usage
def main():
    api = DomainInfoAPI()
    domain = "github.com"
    info = api.get_domain_info(domain)
    print(json.dumps(info, indent=2))

if __name__ == "__main__":
    main()
