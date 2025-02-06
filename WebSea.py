from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.text import Text
from rich import print as rprint
import requests
import socket
import whois
import time
import dns.resolver
import ssl
import OpenSSL
import asyncio
import aiohttp
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any
import subprocess

console = Console()

def get_banner():
    banner = """
    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃    🌊 WebSea - Website Scanner 🔍    ┃
     ┃      Website Analysis Tool v2.0      ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    """
    return Panel(
        Text(banner, style="bold blue", justify="center"),
        border_style="blue",
        padding=(1, 2)
    )

async def check_ssl(domain: str) -> Dict[str, Any]:
    try:
        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        
        return {
            'issuer': dict(x509.get_issuer().get_components()),
            'subject': dict(x509.get_subject().get_components()),
            'expires': datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'),
            'valid': x509.has_expired() == False
        }
    except Exception as e:
        return {'error': str(e)}

async def check_response_time(url: str) -> float:
    async with aiohttp.ClientSession() as session:
        start_time = time.time()
        async with session.get(url) as response:
            end_time = time.time()
            return end_time - start_time

async def find_subdomains(domain: str) -> List[str]:
    common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test']
    found_subdomains = []
    
    for sub in common_subdomains:
        try:
            subdomain = f"{sub}.{domain}"
            ip = await asyncio.get_event_loop().getaddrinfo(subdomain, None)
            found_subdomains.append(subdomain)
        except:
            continue
    
    return found_subdomains

async def analyze_security_headers(headers: Dict) -> Dict[str, str]:
    security_headers = {
        'Strict-Transport-Security': 'Missing',
        'Content-Security-Policy': 'Missing',
        'X-Frame-Options': 'Missing',
        'X-Content-Type-Options': 'Missing',
        'X-XSS-Protection': 'Missing',
        'Referrer-Policy': 'Missing'
    }
    
    for header in security_headers.keys():
        if header in headers:
            security_headers[header] = headers[header]
    
    return security_headers

async def check_advanced_vulnerabilities(url: str) -> Dict[str, Any]:
    vulnerabilities = {
        'sql_injection': [],
        'xss': [],
        'open_ports': [],
        'directory_listing': [],
        'server_info': {},
        'weak_headers': [],
        'csrf': False,
        'xxe': [],
        'ssrf': [],
        'file_inclusion': [],
        'command_injection': [],
        'open_redirects': [],
        'cors_misconfig': [],
        'http_methods': [],
        'sensitive_files': [],
        'wordpress_vulns': [],
        'ssl_vulnerabilities': []
    }
    
    async def test_advanced_sql_injection(url: str) -> List[str]:
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "admin' --",
            "admin' #",
            "' OR 'x'='x",
            "') OR ('1'='1",
            "1' ORDER BY 1--",
            "1' GROUP BY 1--",
            "' HAVING 1=1--",
            "')) OR 1=1--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            "') UNION SELECT @@version--"
        ]
        vulnerable_params = []
        
        params = ['id', 'user', 'username', 'password', 'email', 'search', 'q', 'query', 'page', 'category']
        
        async with aiohttp.ClientSession() as session:
            for param in params:
                for payload in payloads:
                    try:
                        test_url = f"{url}?{param}={payload}"
                        async with session.get(test_url) as response:
                            text = await response.text()
                            if any(error in text.lower() for error in [
                                'sql', 'mysql', 'sqlite', 'postgresql',
                                'ora-', 'odbc', 'syntax error', 'microsoft sql'
                            ]):
                                vulnerable_params.append(f"SQL-инъекция в параметре {param}: {payload}")
                    except:
                        continue
        return vulnerable_params

    async def test_advanced_xss(url: str) -> List[str]:
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "><script>alert(1)</script>",
            "</script><script>alert(1)</script>",
            "' onclick='alert(1)",
            "' onfocus='alert(1)",
            "' onmouseover='alert(1)",
            "<img src=x onerror=prompt(1)>",
            "<a href='javascript:alert(1)'>click</a>"
        ]
        vulnerable_params = []
        
        params = ['q', 'search', 'query', 'id', 'name', 'message', 'comment']
        
        async with aiohttp.ClientSession() as session:
            for param in params:
                for payload in payloads:
                    try:
                        test_url = f"{url}?{param}={payload}"
                        async with session.get(test_url) as response:
                            text = await response.text()
                            if payload.lower() in text.lower():
                                vulnerable_params.append(f"XSS в параметре {param}: {payload}")
                    except:
                        continue
        return vulnerable_params

    async def check_sensitive_files(url: str) -> List[str]:
        sensitive_files = [
            '.git/HEAD',
            '.env',
            'wp-config.php',
            'config.php',
            '.htaccess',
            'robots.txt',
            'sitemap.xml',
            'backup/',
            'admin/',
            'phpinfo.php',
            '.svn/',
            '.DS_Store',
            'web.config',
            'database.yml',
            'credentials.txt',
            'backup.sql',
            'dump.sql',
            '.bash_history',
            '.ssh/id_rsa',
            'access.log'
        ]
        found_files = []
        
        async with aiohttp.ClientSession() as session:
            for file in sensitive_files:
                try:
                    test_url = f"{url}/{file}"
                    async with session.get(test_url) as response:
                        if response.status == 200:
                            found_files.append(f"Найден чувствительный файл: {file}")
                except:
                    continue
        return found_files

    async def check_ssrf(url: str) -> List[str]:
        ssrf_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://[::1]',
            'http://169.254.169.254',
            'file:///etc/passwd',
            'dict://localhost:11211/'
        ]
        vulnerable_params = []
        
        params = ['url', 'redirect', 'link', 'src', 'dest']
        
        async with aiohttp.ClientSession() as session:
            for param in params:
                for payload in ssrf_payloads:
                    try:
                        test_url = f"{url}?{param}={payload}"
                        async with session.get(test_url) as response:
                            if response.status == 200:
                                vulnerable_params.append(f"Возможная SSRF в параметре {param}: {payload}")
                    except:
                        continue
        return vulnerable_params

    async def check_cors_misconfig(url: str) -> List[str]:
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            try:
                headers = {
                    'Origin': 'https://evil.com'
                }
                async with session.get(url, headers=headers) as response:
                    cors_headers = response.headers
                    if 'Access-Control-Allow-Origin' in cors_headers:
                        if cors_headers['Access-Control-Allow-Origin'] == '*':
                            vulnerabilities.append("CORS: Разрешены все домены (Access-Control-Allow-Origin: *)")
                        elif 'evil.com' in cors_headers['Access-Control-Allow-Origin']:
                            vulnerabilities.append("CORS: Небезопасная конфигурация - принимает произвольные домены")
                    
                    if 'Access-Control-Allow-Credentials' in cors_headers:
                        if cors_headers['Access-Control-Allow-Credentials'].lower() == 'true':
                            vulnerabilities.append("CORS: Разрешены учетные данные с произвольных доменов")
            except:
                pass
        return vulnerabilities

    vulnerabilities['sql_injection'] = await test_advanced_sql_injection(url)
    vulnerabilities['xss'] = await test_advanced_xss(url)
    vulnerabilities['sensitive_files'] = await check_sensitive_files(url)
    vulnerabilities['ssrf'] = await check_ssrf(url)
    vulnerabilities['cors_misconfig'] = await check_cors_misconfig(url)
    
    async with aiohttp.ClientSession() as session:
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'DEBUG']
        for method in methods:
            try:
                async with session.request(method, url) as response:
                    if response.status != 405:  # Method Not Allowed
                        vulnerabilities['http_methods'].append(f"Разрешен метод {method}")
            except:
                continue

    return vulnerabilities

async def analyze_website(url: str) -> Dict[str, Any]:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        domain = url.split('//')[-1].split('/')[0]
        
        ip = socket.gethostbyname(domain)
        w = whois.whois(domain)
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                headers = dict(response.headers)
        
        ssl_info = await check_ssl(domain)
        response_time = await check_response_time(url)
        subdomains = await find_subdomains(domain)
        security_headers = await analyze_security_headers(headers)
        
        dns_records = {}
        record_types = ['A', 'MX', 'NS', 'TXT', 'AAAA', 'CNAME']
        
        for record_type in record_types:
            try:
                records = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = records
            except Exception:
                continue
        
        vulnerabilities = await check_advanced_vulnerabilities(url)
        
        return {
            'ip': ip,
            'whois': w,
            'headers': headers,
            'dns': dns_records,
            'ssl': ssl_info,
            'response_time': response_time,
            'subdomains': subdomains,
            'security_headers': security_headers,
            'vulnerabilities': vulnerabilities  
        }
    except Exception as e:
        return f"Error: {str(e)}"

def format_whois_data(whois_data):
    important_fields = [
        'domain_name', 'registrar', 'creation_date', 
        'expiration_date', 'updated_date', 'name_servers'
    ]
    formatted_data = []
    for field in important_fields:
        if hasattr(whois_data, field) and getattr(whois_data, field):
            value = getattr(whois_data, field)
            if isinstance(value, list):
                value = "\n\t".join(str(v) for v in value)
            formatted_data.append(f"[bold cyan]{field.replace('_', ' ').title()}:[/]\n\t{value}")
    return "\n".join(formatted_data)

async def main():
    console.clear()
    console.print(get_banner())
    
    url = console.input("[bold yellow]┏━━━━━━━━━━━━━━━━━━━━\n┃ Enter website URL: [/]")
    
    with Progress(
        "[progress.description]{task.description}",
        SpinnerColumn("dots"),
        TextColumn("[bold blue]{task.fields[status]}"),
        transient=True,
    ) as progress:
        task = progress.add_task(
            description="[cyan]Scanning...",
            status="Preparing analysis...",
            total=None
        )
        result = await analyze_website(url)
    
    if isinstance(result, str):
        console.print(Panel(f"[red]{result}[/]", 
                          title="❌ Error", 
                          border_style="red"))
        return
    
    console.print("\n[bold green]🎯 Analysis Results:[/]\n")
    
    console.print(Panel(
        f"[bold cyan]🌐 Domain:[/] {url}\n"
        f"[bold cyan]🔍 IP Address:[/] {result['ip']}\n"
        f"[bold cyan]⏱️ Response Time:[/] {result['response_time']:.2f} seconds",
        title="📌 Basic Information",
        border_style="green",
        padding=(1, 2)
    ))
    
    if 'error' not in result['ssl']:
        ssl_info = result['ssl']
        console.print(Panel(
            f"[bold cyan]Issuer:[/] {ssl_info['issuer']}\n"
            f"[bold cyan]Expires:[/] {ssl_info['expires']}\n"
            f"[bold cyan]Valid:[/] {'✅' if ssl_info['valid'] else '❌'}",
            title="🔒 SSL Certificate",
            border_style="cyan",
            padding=(1, 2)
        ))
    
    if result['subdomains']:
        console.print(Panel(
            "\n".join(f"• {subdomain}" for subdomain in result['subdomains']),
            title="🌐 Discovered Subdomains",
            border_style="blue",
            padding=(1, 2)
        ))
    
    security_status = "\n".join(
        f"[bold cyan]{header}:[/] {'✅' if value != 'Missing' else '❌'} {value}"
        for header, value in result['security_headers'].items()
    )
    console.print(Panel(
        security_status,
        title="🛡️ Security Headers",
        border_style="red",
        padding=(1, 2)
    ))
    
    console.print(Panel(
        format_whois_data(result['whois']),
        title="📋 WHOIS Information",
        border_style="blue",
        padding=(1, 2)
    ))
    
    important_headers = ['Server', 'X-Powered-By', 'Content-Type', 'Content-Security-Policy']
    headers_info = "\n".join([
        f"[bold cyan]{k}:[/] {v}" 
        for k, v in result['headers'].items() 
        if k in important_headers or k.startswith('X-')
    ])
    console.print(Panel(
        headers_info,
        title="🔒 HTTP Headers",
        border_style="yellow",
        padding=(1, 2)
    ))
    
    dns_info = []
    for record_type, records in result['dns'].items():
        dns_info.append(f"[bold cyan]{record_type}:[/]")
        for record in records:
            dns_info.append(f"\t{str(record)}")
    
    console.print(Panel(
        "\n".join(dns_info),
        title="🌍 DNS Records",
        border_style="magenta",
        padding=(1, 2)
    ))
    
    if result['vulnerabilities']:
        vuln_info = ""
        
        for vuln_type, findings in result['vulnerabilities'].items():
            if findings:  # Если есть находки
                if isinstance(findings, list):
                    if len(findings) > 0:
                        vuln_info += f"[red]{vuln_type.upper()}:[/]\n"
                        for finding in findings:
                            vuln_info += f"• {finding}\n"
                        vuln_info += "\n"
                elif isinstance(findings, bool) and findings:
                    vuln_info += f"[red]{vuln_type.upper()}:[/] Уязвимость обнаружена\n\n"
                elif isinstance(findings, dict) and findings:
                    vuln_info += f"[red]{vuln_type.upper()}:[/]\n"
                    for key, value in findings.items():
                        vuln_info += f"• {key}: {value}\n"
                    vuln_info += "\n"
        
        if vuln_info:
            console.print(Panel(
                vuln_info,
                title="🔓 Результаты сканирования уязвимостей",
                border_style="red",
                padding=(1, 2)
            ))
        else:
            console.print(Panel(
                "[green]Уязвимостей не обнаружено![/]",
                title="🛡️ Результаты сканирования уязвимостей",
                border_style="green",
                padding=(1, 2)
            ))
    
    console.print("\n[bold green]✅ Scan completed successfully![/]")

if __name__ == "__main__":
    asyncio.run(main())