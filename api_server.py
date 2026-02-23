#!/usr/bin/env python3
"""
BeforeClick Domain Info API Server
Fetches real WHOIS data from reliable sources
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import sys
import urllib.request
import urllib.error
from datetime import datetime

class DomainInfoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests for domain info"""
        # Parse the URL and query parameters
        parsed_url = urlparse(self.path)
        
        # Enable CORS
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        if parsed_url.path == '/api/domain-info':
            query_params = parse_qs(parsed_url.query)
            domain = query_params.get('domain', [None])[0]
            
            if not domain:
                self.wfile.write(json.dumps({'error': 'No domain provided'}).encode())
                return
            
            # Clean domain name
            domain = domain.lower().replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
            
            # Get real domain info from WHOIS API
            domain_info = self.get_real_whois_data(domain)
            self.wfile.write(json.dumps(domain_info).encode())
        
        elif parsed_url.path == '/api/health':
            self.wfile.write(json.dumps({'status': 'ok', 'service': 'domain-info'}).encode())
        
        else:
            self.wfile.write(json.dumps({'error': 'Endpoint not found'}).encode())
    
    def do_OPTIONS(self):
        """Handle CORS OPTIONS requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def get_real_whois_data(self, domain):
        """Fetch real WHOIS data from system whois command (primary) and APIs (fallback)"""
        # Primary method: Use system whois command (most reliable on Unix/Linux/macOS)
        result = self.try_whois_command(domain)
        if result and result.get('status') == 'success':
            print(f"[✓] Got WHOIS data for {domain} from system whois command")
            return result
        
        # Fallback: Try free WHOIS API sources without SSL verification issues
        apis = [
            f'http://whois.arin.net/rest/ip/{domain}',  # Basic fallback
        ]
        
        for api_url in apis:
            try:
                req = urllib.request.Request(api_url, headers={
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
                })
                with urllib.request.urlopen(req, timeout=8) as response:
                    data = response.read().decode()
                    if data:
                        print(f"[✓] Got data for {domain} from {api_url}")
                        return self.parse_api_response({'raw': data}, domain)
            except Exception as e:
                print(f"[!] API fallback error: {str(e)[:40]}")
                continue
        
        # Last resort - return placeholder with instructions
        return {
            'domain': domain,
            'status': 'unavailable',
            'error': 'WHOIS data temporarily unavailable for this domain',
            'message': 'Try searching on https://whatsmydns.net/domain-age for real data'
        }
    
    def try_whois_command(self, domain):
        """Try to use system whois command"""
        try:
            import subprocess
            result = subprocess.run(
                ['whois', domain],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout:
                return self.parse_whois_text(result.stdout, domain)
        except:
            pass
        
        return None
    
    def parse_whois_text(self, whois_text, domain):
        """Parse plain text WHOIS output"""
        try:
            lines = whois_text.split('\n')
            created_date = None
            expiry_date = None
            registrar = None
            
            for line in lines:
                line_lower = line.lower()
                
                # Look for creation date
                if 'creation date' in line_lower or 'created date' in line_lower or 'created on' in line_lower:
                    date_part = line.split(':', 1)[-1].strip()
                    if date_part:
                        created_date = date_part
                
                # Look for expiry date
                if 'expir' in line_lower or 'renewal date' in line_lower:
                    date_part = line.split(':', 1)[-1].strip()
                    if date_part:
                        expiry_date = date_part
                
                # Look for registrar
                if 'registrar' in line_lower and ':' in line:
                    registrar = line.split(':', 1)[-1].strip()
            
            if created_date:
                return self.build_response(domain, created_date, expiry_date, registrar)
        
        except Exception as e:
            print(f"[!] Error parsing WHOIS: {e}")
        
        return None
    
    def parse_api_response(self, data, domain):
        """Parse API response"""
        try:
            # Different API formats
            if 'WhoisRecord' in data:
                record = data['WhoisRecord']
                return self.build_response(
                    domain,
                    record.get('createdDate'),
                    record.get('expiresDate'),
                    record.get('registrar')
                )
            
            elif 'creation_date' in data:
                return self.build_response(
                    domain,
                    data.get('creation_date'),
                    data.get('expiration_date'),
                    data.get('registrar')
                )
            
            elif 'result' in data and isinstance(data['result'], dict):
                result = data['result']
                return self.build_response(
                    domain,
                    result.get('created_date'),
                    result.get('expiration_date'),
                    result.get('registrar')
                )
        
        except Exception as e:
            print(f"[!] Error parsing API: {e}")
        
        return None
    
    def build_response(self, domain, created_date, expiry_date, registrar):
        """Build standardized response"""
        try:
            domain_age_years = 'Unknown'
            domain_age_days = 0
            
            if created_date:
                try:
                    # Extract just the date part
                    date_str = str(created_date).split('T')[0].split(' ')[0]
                    
                    # Try to parse different formats
                    created = None
                    for fmt in ['%Y-%m-%d', '%d-%m-%Y', '%m/%d/%Y']:
                        try:
                            created = datetime.strptime(date_str, fmt)
                            break
                        except:
                            continue
                    
                    if created:
                        now = datetime.now()
                        domain_age_days = (now - created).days
                        domain_age_years = f"{domain_age_days / 365.25:.1f}"
                        
                        print(f"[✓] {domain}: {domain_age_years} years old (created: {created_date})")
                except Exception as e:
                    print(f"[!] Date parsing error: {e}")
            
            # Calculate risk
            risk_score = 10
            if domain_age_days > 0:
                if domain_age_days < 30:
                    risk_score = 80
                elif domain_age_days < 90:
                    risk_score = 75
                elif domain_age_days < 365:
                    risk_score = 50
                elif domain_age_days < 1825:
                    risk_score = 25
            
            return {
                'domain': domain,
                'status': 'success',
                'created_date': str(created_date) if created_date else 'Unknown',
                'expiry_date': str(expiry_date) if expiry_date else 'Unknown',
                'domain_age_years': domain_age_years,
                'domain_age_days': domain_age_days,
                'registrar': str(registrar) if registrar else 'Unknown',
                'risk_score': risk_score,
                'source': 'whois-data'
            }
        
        except Exception as e:
            print(f"[!] Response building error: {e}")
            return None
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


def run_server(port=8001):
    """Start the domain info server"""
    server_address = ('127.0.0.1', port)
    httpd = HTTPServer(server_address, DomainInfoHandler)
    print(f"🚀 Domain Info Server running on http://127.0.0.1:{port}")
    print(f"📍 Endpoint: http://127.0.0.1:{port}/api/domain-info?domain=example.com")
    print(f"✅ Fetching REAL WHOIS data from multiple sources...")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n✅ Server stopped")
        sys.exit(0)


if __name__ == '__main__':
    port = 8001
    run_server(port)




