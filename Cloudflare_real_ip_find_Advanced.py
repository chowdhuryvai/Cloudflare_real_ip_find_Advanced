import json
import requests
import socket
import dns.resolver
from prettytable import PrettyTable
import sys
import time
import subprocess
import os


def banner():
    print("\033[1;36m")
    print("""
  ____ _                            _                 
 / ___| |__   ___ _ __ _   _ _   _| | __ _ _   _ ___ 
| |   | '_ \\ / _ \\ '__| | | | | | | |/ _` | | | / __|
| |___| | | |  __/ |  | |_| | |_| | | (_| | |_| \\__ \\
 \\____|_| |_|\\___|_|   \\__,_|\\__,_|_|\\__,_|\\__, |___/
          |_ _| | | | |__  _   _ _   _ _   |___/     
           | || | | | '_ \\| | | | | | | | | | | |    
           | || |_| | |_) | |_| | |_| | |_| |_| |    
          |___\\___/|_.__/ \\__,_|\\__, |\\__,_|\\__,_|   
                               |___/                 
    """)
    print("\033[1;32m" + "=" * 60)
    print("🔍 Advanced IP Analysis Tool")
    print("👨‍💻 Created by: ChowdhuryVai")
    print("📱 Telegram: https://t.me/darkvaiadmin")
    print("📢 Channel: https://t.me/windowspremiumkey")
    print("🌐 Website: https://crackyworld.com/")
    print("=" * 60 + "\033[0m")
    print()


def loading_animation(message):
    print(f"\033[1;33m{message}", end="")
    for i in range(3):
        print(".", end="", flush=True)
        time.sleep(0.5)
    print("\033[0m")


def install_dependencies():
    """Install required dependencies automatically"""
    try:
        import dns.resolver
        print("\033[1;32m✓ All dependencies are already installed\033[0m")
    except ImportError:
        print("\033[1;33mInstalling dnspython library...\033[0m")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "dnspython"])
            print("\033[1;32m✓ Dependencies installed successfully!\033[0m")
        except Exception as e:
            print(f"\033[1;31m✗ Failed to install dependencies: {e}\033[0m")
            return False
    return True


def nslookup_advanced(domain):
    """Multiple methods to resolve domain to IP addresses"""
    ip_list = []
    
    print(f"\033[1;33mResolving domain: {domain}\033[0m")
    
    # Method 1: Using socket.getaddrinfo (Standard method)
    try:
        loading_animation("Method 1: Standard DNS resolution")
        result = socket.getaddrinfo(domain, None)
        for res in result:
            ip = res[4][0]
            if ip not in ip_list and ip != '0.0.0.0':
                ip_list.append(ip)
        print(f"\033[1;32m✓ Socket method found {len([ip for ip in ip_list if 'socket' not in ip])} IPs\033[0m")
    except Exception as e:
        print(f"\033[1;31m✗ Socket method failed: {e}\033[0m")

    # Method 2: Using socket.gethostbyname_ex
    try:
        loading_animation("Method 2: Hostname resolution")
        result = socket.gethostbyname_ex(domain)
        for ip in result[2]:
            if ip not in ip_list and ip != '0.0.0.0':
                ip_list.append(ip)
        print(f"\033[1;32m✓ Hostname method found {len([ip for ip in ip_list if 'hostname' not in ip])} IPs\033[0m")
    except Exception as e:
        print(f"\033[1;31m✗ Hostname method failed: {e}\033[0m")

    # Method 3: Using dnspython library (A records)
    try:
        loading_animation("Method 3: DNS A records")
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ip = str(rdata)
            if ip not in ip_list:
                ip_list.append(ip)
        print(f"\033[1;32m✓ DNS A records found {len([ip for ip in ip_list if 'dns' not in ip])} IPs\033[0m")
    except Exception as e:
        print(f"\033[1;31m✗ DNS A records failed: {e}\033[0m")

    # Method 4: Using dnspython library (AAAA records - IPv6)
    try:
        loading_animation("Method 4: DNS AAAA records")
        answers = dns.resolver.resolve(domain, 'AAAA')
        for rdata in answers:
            ip = str(rdata)
            if ip not in ip_list:
                ip_list.append(ip)
        print(f"\033[1;32m✓ DNS AAAA records found {len([ip for ip in ip_list if ':' in ip])} IPs\033[0m")
    except Exception as e:
        print(f"\033[1;33m⚠ DNS AAAA records: No IPv6 addresses\033[0m")

    # Method 5: Using system nslookup command
    try:
        loading_animation("Method 5: System nslookup")
        result = subprocess.check_output(['nslookup', domain], timeout=10, stderr=subprocess.STDOUT)
        result = result.decode('utf-8', errors='ignore')
        for line in result.split('\n'):
            if 'Address:' in line and not line.startswith('Server:') and not line.startswith('Address:'):
                ip = line.split(':')[1].strip()
                if ip not in ip_list and ip != '0.0.0.0' and not ip.startswith('127.'):
                    ip_list.append(ip)
        print(f"\033[1;32m✓ System nslookup found {len([ip for ip in ip_list if 'system' not in ip])} IPs\033[0m")
    except Exception as e:
        print(f"\033[1;33m⚠ System nslookup failed: {e}\033[0m")

    # Remove duplicates and invalid IPs
    final_ips = []
    for ip in ip_list:
        if (isinstance(ip, str) and 
            ip not in final_ips and 
            ip != '0.0.0.0' and 
            not ip.startswith('127.') and
            len(ip) > 6):
            final_ips.append(ip)

    print(f"\033[1;32m🎯 Total unique IP addresses found: {len(final_ips)}\033[0m")
    
    if final_ips:
        print("\033[1;36m📋 Found IP addresses:\033[0m")
        for ip in final_ips:
            print(f"   \033[1;33m• {ip}\033[0m")
    
    return final_ips


def find_real_ip(ip_list):
    url = 'https://api.criminalip.io/v1/asset/ip/report'
    
    # API Configuration
    API_KEY = "73GGdVSnDb0YwxsTaxtuqtdC5DCvY3FDRB8TG9oC9FgYqAJyMsFghTQhlXhA"
    HEADERS = {
        "x-api-key": API_KEY,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    results = []
    total_ips = len(ip_list)
    
    for index, ip in enumerate(ip_list, 1):
        print(f"\033[1;34m[{index}/{total_ips}] Analyzing IP: {ip}\033[0m")
        
        params = {
            'ip': ip
        }

        try:
            res = requests.get(url=url, params=params, headers=HEADERS, timeout=30)
            
            if res.status_code != 200:
                print(f"\033[1;31m✗ HTTP Error {res.status_code} for {ip}\033[0m")
                continue
                
            res_data = res.json()

            if res_data.get('status') == 200:
                
                protected_ip_data = res_data.get('protected_ip', {}).get('data', [])
                real_ip_addresses = [d['ip_address'] for d in protected_ip_data if 'ip_address' in d]

                org_data = res_data.get('whois', {}).get('data', [])
                org_name = org_data[0].get('org_name', 'Unknown Organization') if org_data else 'Unknown Organization'

                opened_ports_data = res_data.get('port', {}).get('data', [])
                opened_ports = [str(port.get('open_port_no', 'Unknown')) for port in opened_ports_data]

                results.append({
                    'ip': res_data.get('ip', ip),
                    'real_ip': real_ip_addresses,
                    'org': org_name,
                    'opened_ports': opened_ports,
                })
                print(f"\033[1;32m✓ Successfully analyzed {ip}\033[0m")
            else:
                error_msg = res_data.get('message', 'API request failed')
                print(f"\033[1;31m✗ API Error for {ip}: {error_msg}\033[0m")
                
        except requests.exceptions.RequestException as e:
            print(f"\033[1;31m✗ Network error for {ip}: {str(e)}\033[0m")
        except json.JSONDecodeError:
            print(f"\033[1;31m✗ Invalid JSON response for {ip}\033[0m")
        except Exception as e:
            print(f"\033[1;31m✗ Unexpected error for {ip}: {str(e)}\033[0m")

    return results


def print_result(results):
    if not results:
        print("\033[1;31mNo analysis results to display.\033[0m")
        return
        
    print("\n" + "=" * 80)
    print("\033[1;35m" + "📊 ANALYSIS RESULTS".center(80) + "\033[0m")
    print("=" * 80)
    
    table = PrettyTable()
    table.field_names = ["\033[1;36mIP Address\033[0m", "\033[1;36mReal IP Address\033[0m", "\033[1;36mOrganization\033[0m", "\033[1;36mOpened Ports\033[0m"]
    
    for r in results:
        ip = f"\033[1;33m{r['ip']}\033[0m"
        real_ip = '\n'.join([f"\033[1;32m{ip}\033[0m" for ip in r['real_ip']]) if r['real_ip'] else "\033[1;31mNot Found\033[0m"
        org = f"\033[1;34m{r['org'][:30]}...\033[0m" if len(r['org']) > 30 else f"\033[1;34m{r['org']}\033[0m"
        ports = ', '.join(r['opened_ports'][:5]) + ('...' if len(r['opened_ports']) > 5 else '')
        ports = f"\033[1;35m{ports}\033[0m" if ports else "\033[1;31mNo open ports\033[0m"
        
        table.add_row([ip, real_ip, org, ports])
    
    table.align = "l"
    table.max_width = 20
    print(table)
    
    print("\n" + "=" * 80)
    print("\033[1;32m" + f"✅ Analysis completed! Total results: {len(results)}".center(80) + "\033[0m")
    print("=" * 80)


def test_domain_resolution():
    """Test with popular domains to verify functionality"""
    test_domains = ["google.com", "github.com", "facebook.com"]
    
    print("\033[1;36m🧪 Testing domain resolution with popular domains...\033[0m")
    for domain in test_domains:
        try:
            ip = socket.gethostbyname(domain)
            print(f"\033[1;32m✓ {domain} -> {ip}\033[0m")
        except Exception as e:
            print(f"\033[1;31m✗ {domain} failed: {e}\033[0m")


def main():
    try:
        banner()
        
        # Install dependencies automatically
        if not install_dependencies():
            print("\033[1;31m✗ Cannot continue without required dependencies.\033[0m")
            return
        
        # Test domain resolution
        test_domain_resolution()
        print()
        
        print("\033[1;33m🌐 Domain Analysis:\033[0m")
        domain = input("Enter domain (e.g., google.com): ").strip()
        
        if not domain:
            print("\033[1;31m✗ Domain cannot be empty.\033[0m")
            return
            
        # Remove http:// or https:// if present
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        
        ip_list = nslookup_advanced(domain)
        
        if not ip_list:
            print("\033[1;31m✗ No IP addresses found for the domain. Please check the domain name.\033[0m")
            return
            
        results = find_real_ip(ip_list)
        print_result(results)
        
    except KeyboardInterrupt:
        print("\n\n\033[1;31m❌ Operation cancelled by user.\033[0m")
    except Exception as e:
        print(f"\n\033[1;31m💥 Unexpected error: {str(e)}\033[0m")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n\033[1;31m👋 Thank you for using ChowdhuryVai's IP Analysis Tool!\033[0m")
