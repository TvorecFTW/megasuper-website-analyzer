import re  # Добавьте эту строку в импорты
from flask import Flask, request, jsonify
import requests
import whois
import socket
import dns.resolver
import ssl
import os
import json
from datetime import datetime
from urllib.parse import urlparse, urljoin
import hashlib
import html2text
from bs4 import BeautifulSoup

app = Flask(__name__)

# Конфигурация
DEFAULT_VIRUSTOTAL_API_KEY = "YOUR_API_KEY"
MAX_DEPTH = 2
TIMEOUT = 10
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

# Функции анализа
def get_html(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=True)
        response.raise_for_status()
        return response.text
    except requests.exceptions.SSLError:
        try:
            response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
            return response.text
        except Exception as e:
            return f"Ошибка при получении HTML (SSL): {str(e)}"
    except Exception as e:
        return f"Ошибка при получении HTML: {str(e)}"

def get_ip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
        except socket.herror:
            hostname, aliases = ip, []
        return {
            "IP адрес": ip,
            "Хост": hostname,
            "Алиасы": aliases,
            "Открытые порты": scan_ports(ip),
            "Геолокация": get_geo_info(ip)
        }
    except Exception as e:
        return f"Ошибка при получении IP информации: {str(e)}"

def scan_ports(ip, ports_to_scan=[80, 443, 21, 22, 25, 53, 3306, 3389]):
    open_ports = {}
    for port in ports_to_scan:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                open_ports[port] = service
    return open_ports

def get_geo_info(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=TIMEOUT)
        data = response.json()
        if data['status'] == 'success':
            return {
                "Страна": data.get('country', 'N/A'),
                "Регион": data.get('regionName', 'N/A'),
                "Город": data.get('city', 'N/A'),
                "Провайдер": data.get('isp', 'N/A'),
                "ORG": data.get('org', 'N/A')
            }
        return "Геоданные не найдены"
    except:
        return "Не удалось получить геоданные"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        if not w:
            return "Информация WHOIS не найдена"
        result = {}
        for key, value in w.items():
            if not key.startswith('_') and value:
                if isinstance(value, list):
                    value = ', '.join(str(v) for v in value if v)
                result[key] = str(value)
        return result
    except Exception as e:
        return f"Ошибка WHOIS: {str(e)}"

def check_virustotal(domain, api_key):
    if not api_key or api_key == "YOUR_API_KEY":
        return "Необходимо указать API ключ VirusTotal"
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": api_key}
        response = requests.get(url, headers=headers, timeout=TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            return {
                "Репутация": data.get('data', {}).get('attributes', {}).get('reputation', 'N/A'),
                "Статистика": data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}),
                "Категории": data.get('data', {}).get('attributes', {}).get('categories', {}),
                "Дата последней проверки": data.get('data', {}).get('attributes', {}).get('last_analysis_date', 'N/A')
            }
        return f"Ошибка запроса к VirusTotal: {response.status_code}"
    except Exception as e:
        return f"Ошибка VirusTotal: {str(e)}"

def save_web_snapshot(url):
    try:
        html = get_html(url)
        # Vercel не позволяет сохранять файлы постоянно
        return {
            "Размер HTML": f"{len(html)/1024:.2f} KB",
            "Хэш MD5": hashlib.md5(html.encode()).hexdigest(),
            "Статус": "Файлы не сохраняются на Vercel (read-only файловая система)"
        }
    except Exception as e:
        return f"Ошибка: {str(e)}"

def recursive_parse(url, visited=None, depth=0, progress_callback=None):
    if visited is None:
        visited = set()
    if depth > MAX_DEPTH or url in visited:
        return []
    visited.add(url)
    results = []
    try:
        html = get_html(url)
        soup = BeautifulSoup(html, 'html.parser')
        page_data = {
            "URL": url,
            "Заголовок": soup.title.string if soup.title else "Без заголовка",
            "Мета-описание": get_meta_description(soup),
            "Количество ссылок": len(soup.find_all('a')),
            "Количество изображений": len(soup.find_all('img')),
            "Количество форм": len(soup.find_all('form')),
            "JavaScript файлы": get_js_files(soup),
            "CSS файлы": get_css_files(soup)
        }
        links = set()
        for link in soup.find_all('a', href=True):
            absolute_url = urljoin(url, link['href'])
            if absolute_url.startswith(('http://', 'https://')):
                links.add(absolute_url)
        page_data["Примеры ссылок"] = list(links)[:5]
        results.append(page_data)
        if progress_callback:
            progress = (depth / MAX_DEPTH) * 100
            progress_callback(progress)
        if depth < MAX_DEPTH:
            for link in list(links)[:3]:
                sub_results = recursive_parse(link, visited, depth+1, progress_callback)
                results.extend(sub_results)
    except Exception as e:
        results.append({"URL": url, "Ошибка": str(e)})
    return results

def get_meta_description(soup):
    meta = soup.find('meta', attrs={'name': 'description'})
    return meta['content'] if meta and 'content' in meta.attrs else "Не найдено"

def get_js_files(soup):
    scripts = soup.find_all('script', src=True)
    return [script['src'] for script in scripts if script['src']]

def get_css_files(soup):
    links = soup.find_all('link', rel='stylesheet')
    return [link['href'] for link in links if link['href']]

def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_before = cert.get('notBefore', '')
                not_after = cert.get('notAfter', '')
                def parse_name(name):
                    if isinstance(name, str):
                        return name
                    if isinstance(name, tuple):
                        return dict(x[0] for x in name)
                    return str(name)
                return {
                    "Издатель": parse_name(cert.get('issuer', 'N/A')),
                    "Владелец": parse_name(cert.get('subject', 'N/A')),
                    "Версия": cert.get('version', 'N/A'),
                    "Действителен с": not_before,
                    "Действителен до": not_after,
                    "Серийный номер": cert.get('serialNumber', 'N/A'),
                    "Алгоритм подписи": cert.get('signatureAlgorithm', 'N/A'),
                    "SAN": get_san(cert)
                }
    except Exception as e:
        return f"Ошибка SSL: {str(e)}"

def get_san(cert):
    if not cert:
        return []
    san = []
    for field in cert.get('subjectAltName', []):
        if field[0].lower() == 'dns':
            san.append(field[1])
    return san or ["Не найдены"]

def get_dns_records(domain):
    try:
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
                if answers.rrset:
                    records[record_type] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            except Exception as e:
                records[record_type] = f"Ошибка: {str(e)}"
        return records if records else "DNS записи не найдены"
    except Exception as e:
        return f"Ошибка DNS: {str(e)}"

def get_ip_neighbors(domain):
    try:
        ip = socket.gethostbyname(domain)
        base_ip = '.'.join(ip.split('.')[:3])
        neighbors = []
        for i in range(int(ip.split('.')[-1])-5, int(ip.split('.')[-1])+6):
            if 1 <= i <= 254:
                neighbor_ip = f"{base_ip}.{i}"
                if neighbor_ip != ip:
                    try:
                        host = socket.gethostbyaddr(neighbor_ip)[0]
                        neighbors.append({
                            "IP": neighbor_ip,
                            "Хост": host,
                            "Порты": scan_ports(neighbor_ip, [80, 443])
                        })
                    except:
                        continue
        return neighbors if neighbors else "Соседние IP не найдены"
    except Exception as e:
        return f"Ошибка поиска соседей: {str(e)}"

def extract_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        domain = re.sub(r'^www\.', '', domain)
        return domain.split(':')[0].split('/')[0]
    except:
        return url

# Маршруты API
@app.route('/api/quick_scan', methods=['GET'])
def quick_scan():
    url = request.args.get('url')
    domain = extract_domain(url)
    results = {
        'WHOIS': get_whois_info(domain),
        'IP информация': get_ip_info(domain),
        'DNS записи': get_dns_records(domain),
        'SSL сертификат': get_ssl_info(domain),
        'VirusTotal': check_virustotal(domain, DEFAULT_VIRUSTOTAL_API_KEY)
    }
    return jsonify(results)

@app.route('/api/whois', methods=['GET'])
def whois():
    url = request.args.get('url')
    domain = extract_domain(url)
    return jsonify({'WHOIS': get_whois_info(domain)})

@app.route('/api/ip_info', methods=['GET'])
def ip_info():
    url = request.args.get('url')
    domain = extract_domain(url)
    return jsonify({'IP информация': get_ip_info(domain)})

@app.route('/api/virustotal', methods=['GET'])
def virustotal():
    url = request.args.get('url')
    domain = extract_domain(url)
    return jsonify({'VirusTotal': check_virustotal(domain, DEFAULT_VIRUSTOTAL_API_KEY)})

@app.route('/api/dns', methods=['GET'])
def dns():
    url = request.args.get('url')
    domain = extract_domain(url)
    return jsonify({'DNS записи': get_dns_records(domain)})

@app.route('/api/ssl', methods=['GET'])
def ssl():
    url = request.args.get('url')
    domain = extract_domain(url)
    return jsonify({'SSL сертификат': get_ssl_info(domain)})

@app.route('/api/ip_neighbors', methods=['GET'])
def ip_neighbors():
    url = request.args.get('url')
    domain = extract_domain(url)
    return jsonify({'Соседние IP': get_ip_neighbors(domain)})

@app.route('/api/snapshot', methods=['GET'])
def snapshot():
    url = request.args.get('url')
    return jsonify({'Снимок сайта': save_web_snapshot(url)})

@app.route('/api/deep_analysis', methods=['GET'])
def deep_analysis():
    url = request.args.get('url')
    return jsonify({'Глубокий анализ': recursive_parse(url)})

if __name__ == '__main__':
    app.run(debug=True)
else:
    # Для работы на Vercel
    app = app