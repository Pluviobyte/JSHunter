
import json
import csv
import os
import re
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import datetime

from config import Config

@dataclass
class Link:
    url: str
    source: str
    status: str = ''
    size: str = ''
    title: str = ''
    redirect: str = ''
    is_api: bool = False

@dataclass
class SensitiveInfo:
    source: str
    phone: List[str] = field(default_factory=list)
    email: List[str] = field(default_factory=list)
    idcard: List[str] = field(default_factory=list)
    jwt: List[str] = field(default_factory=list)
    google_api: List[str] = field(default_factory=list)
    aws_key: List[str] = field(default_factory=list)
    bearer_token: List[str] = field(default_factory=list)
    oauth_token: List[str] = field(default_factory=list)
    ssh_key: List[str] = field(default_factory=list)
    github_token: List[str] = field(default_factory=list)
    slack_token: List[str] = field(default_factory=list)
    other: List[str] = field(default_factory=list)
    
    def has_data(self) -> bool:
        return any([self.phone, self.email, self.idcard, self.jwt, self.google_api, 
                   self.aws_key, self.bearer_token, self.oauth_token, self.ssh_key,
                   self.github_token, self.slack_token, self.other])

class ResultManager:
    def __init__(self):
        self.js_results: List[Link] = []
        self.url_results: List[Link] = []
        self.info_results: List[SensitiveInfo] = []
        self.domains: Set[str] = set()
        self.js_url_map: Dict[str, str] = {}
        
        self.seen_js: Set[str] = set()
        self.seen_urls: Set[str] = set()
    
    def add_js(self, js_url: str, source: str) -> bool:
        if js_url in self.seen_js:
            return False
        
        self.seen_js.add(js_url)
        self.js_results.append(Link(url=js_url, source=source))
        
        parsed = urlparse(js_url)
        js_path = '/'.join(parsed.path.split('/')[:-1])
        if js_path:
            self.js_url_map[js_url] = f"{parsed.scheme}://{parsed.netloc}{js_path}"
        
        if parsed.netloc:
            self.domains.add(parsed.netloc)
        
        return True
    
    def add_url(self, url: str, source: str, is_api: bool = False) -> bool:
        if url in self.seen_urls:
            return False
        
        self.seen_urls.add(url)
        self.url_results.append(Link(url=url, source=source, is_api=is_api))
        
        parsed = urlparse(url)
        if parsed.netloc:
            self.domains.add(parsed.netloc)
        
        return True
    
    def add_info(self, info: SensitiveInfo):
        self.info_results.append(info)
    
    def get_js_path(self, js_url: str) -> Optional[str]:
        return self.js_url_map.get(js_url)
    
    def get_all_urls(self) -> List[str]:
        all_urls = []
        all_urls.extend([link.url for link in self.js_results])
        all_urls.extend([link.url for link in self.url_results])
        return all_urls
    
    def update_url_status(self, url: str, status: str, size: str, title: str, redirect: str):
        for link in self.js_results:
            if link.url == url:
                link.status = status
                link.size = size
                link.title = title
                link.redirect = redirect
                break
        
        for link in self.url_results:
            if link.url == url:
                link.status = status
                link.size = size
                link.title = title
                link.redirect = redirect
                break
    
    def sort_results(self, target_host: str):
        def sort_key(link):
            is_target = target_host in link.url
            status_priority = 0
            
            if link.status:
                if link.status.startswith('2'):
                    status_priority = 1
                elif link.status.startswith('3'):
                    status_priority = 2
                else:
                    status_priority = 3
            
            return (not is_target, status_priority, link.url)
        
        self.js_results.sort(key=sort_key)
        self.url_results.sort(key=sort_key)
    
    def get_host_from_url(self, url: str) -> str:
        match = re.search(r'([a-z0-9\-]+\.)*([a-z0-9\-]+\.[a-z0-9\-]+)(:[0-9]+)?', url)
        return match.group(0) if match else url
    
    def separate_by_domain(self, links: List[Link], target_host: str) -> tuple:
        target_links = []
        other_links = []
        
        for link in links:
            if target_host in link.url:
                target_links.append(link)
            else:
                other_links.append(link)
        
        return target_links, other_links

    def print_count_only(self, config: Config):
        """快速模式：仅显示统计数量"""
        total_js = len(self.js_results)
        total_urls = len(self.url_results)
        total_domains = len(self.domains)

        print(f"\n\033[96m📊 快速扫描结果统计:\033[0m")
        print(f"  📄 发现JS文件: \033[92m{total_js}\033[0m 个")

        if config.enable_url_scan:
            print(f"  🔗 发现URL链接: \033[92m{total_urls}\033[0m 个")

        if config.enable_secret_scan and self.info_results:
            print(f"  🔐 敏感信息项: \033[92m{len(self.info_results)}\033[0m 个")

        if total_domains > 0:
            print(f"  🌐 涉及域名: \033[92m{total_domains}\033[0m 个")

        # 显示扫描模式信息
        if hasattr(config, 'scan_mode'):
            if config.scan_mode == "quick":
                print(f"  ⚡ 扫描模式: \033[93m快速模式\033[0m (仅主页)")
            elif config.scan_mode == "deep":
                print(f"  🔍 扫描模式: \033[93m深度模式\033[0m")

    def print_results(self, config: Config):
        
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[96m[*] JSHunter Security Analysis Results\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
        
        total_js = len(self.js_results)
        total_urls = len(self.url_results)
        total_domains = len(self.domains)
        
        print(f"\033[93m[+] Summary Statistics:\033[0m")
        print(f"   [JS] JavaScript Files: \033[92m{total_js}\033[0m")
        print(f"   [URL] URL Links: \033[92m{total_urls}\033[0m")
        print(f"   [DOM] Unique Domains: \033[92m{total_domains}\033[0m")
        
        if self.js_results:
            print(f"\n\033[96m[JS] JavaScript Files ({total_js}):\033[0m")
            for i, js in enumerate(self.js_results, 1):
                status_indicator = self.get_console_status_indicator(js.status)
                print(f"   \033[94m{i:3d}.\033[0m {status_indicator} \033[94m{js.url}\033[0m")
                if js.source and js.source != js.url:
                    print(f"        |-- \033[90mSource: {js.source}\033[0m")
        else:
            print(f"\n\033[96m[JS] JavaScript Files:\033[0m")
            print(f"   \033[90mNo JavaScript files found\033[0m")
        
        if config.enable_url_scan and self.url_results:
            print(f"\n\033[96m[URL] URL Links ({total_urls}):\033[0m")
            for i, url in enumerate(self.url_results, 1):
                status_indicator = self.get_console_status_indicator(url.status)
                print(f"   \033[94m{i:3d}.\033[0m {status_indicator} \033[94m{url.url}\033[0m")
                if url.title and url.title.strip():
                    title = url.title[:60] + "..." if len(url.title) > 60 else url.title
                    print(f"        |-- \033[90mTitle: {title.strip()}\033[0m")
                if url.source and url.source != url.url:
                    print(f"        |-- \033[90mSource: {url.source}\033[0m")
        
        if config.enable_api_scan and hasattr(self, 'api_results') and self.api_results:
            print(f"\n\033[96m[API] API Endpoints ({len(self.api_results)}):\033[0m")
            for i, api in enumerate(self.api_results, 1):
                status_indicator = self.get_console_status_indicator(api.status)
                print(f"   \033[94m{i:3d}.\033[0m {status_indicator} \033[94m{api.url}\033[0m")
        
        if config.enable_secret_scan and self.info_results:
            self.print_sensitive_info_enhanced()
        
        if self.domains:
            print(f"\n\033[96m[DOM] Discovered Domains ({total_domains}):\033[0m")
            for i, domain in enumerate(sorted(self.domains), 1):
                print(f"   \033[94m{i:3d}.\033[0m \033[92m[OK]\033[0m {domain}")
        
        print(f"\n\033[96m{'='*60}\033[0m")
        print(f"\033[92m[+] Scan completed successfully!\033[0m")
        print(f"\033[93m[*] Total discovered: {total_js + total_urls} items across {total_domains} domains\033[0m")
        print(f"\033[96m{'='*60}\033[0m")
    
    def print_links(self, links: List[Link]):
        for link in links:
            if link.status:
                status_color = self.get_status_color(link.status)
                url_color = "\033[94m"
                
                info_parts = [f"Status: {link.status}"]
                if link.size:
                    info_parts.append(f"Size: {link.size}")
                if link.title and link.title.strip():
                    title = link.title[:50] + "..." if len(link.title) > 50 else link.title
                    info_parts.append(f"Title: {title}")
                if link.redirect:
                    info_parts.append(f"Redirect: {link.redirect}")
                if link.source:
                    info_parts.append(f"Source: {link.source}")
                
                info = " [ " + ", ".join(info_parts) + " ]"
                
                if link.redirect:
                    print(f"{url_color}{link.url} -> {link.redirect}\033[0m{status_color}{info}\033[0m")
                else:
                    print(f"{url_color}{link.url}\033[0m{status_color}{info}\033[0m")
            else:
                print(f"\033[94m{link.url}\033[0m")
    
    def get_status_color(self, status: str) -> str:
        if status == '0' or '危险' in status or '疑似' in status:
            return "\033[91m"
        elif status.startswith('2'):
            return "\033[92m"
        elif status.startswith('3'):
            return "\033[93m"
        elif status.startswith('4') or status.startswith('5'):
            return "\033[91m"
        else:
            return "\033[37m"
    
    def print_sensitive_info(self):
        all_info = {
            'Phone': [],
            'Email': [],
            'IDcard': [],
            'JWT': [],
            'Other': []
        }
        
        for info in self.info_results:
            for phone in info.phone:
                all_info['Phone'].append((phone, info.source))
            for email in info.email:
                all_info['Email'].append((email, info.source))
            for idcard in info.idcard:
                all_info['IDcard'].append((idcard, info.source))
            for jwt in info.jwt:
                all_info['JWT'].append((jwt, info.source))
            for other in info.other:
                all_info['Other'].append((other, info.source))
        
        for info_type, items in all_info.items():
            if items:
                print(f"\n{info_type}:")
                for item, source in items:
                    print(f"  {item} [ Source: {source} ]")
    
    def export_results(self, output_path: str, config: Config):
        ext = os.path.splitext(output_path)[1].lower()
        
        if ext == '.csv':
            self.export_csv(output_path, config)
        elif ext == '.json':
            self.export_json(output_path, config)
        elif ext == '.html':
            self.export_html(output_path, config)
        else:
            print(f"不支持的导出格式: {ext}")
    
    def export_csv(self, output_path: str, config: Config):
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                writer.writerow(['URL', 'Source', 'Type'])
                
                for js in self.js_results:
                    writer.writerow([js.url, js.source, 'JS'])
                
                for url in self.url_results:
                    writer.writerow([url.url, url.source, 'URL'])
                
                for info in self.info_results:
                    for phone in info.phone:
                        writer.writerow([phone, '', '', '', '', info.source, 'Phone'])
                    for email in info.email:
                        writer.writerow([email, '', '', '', '', info.source, 'Email'])
                    for idcard in info.idcard:
                        writer.writerow([idcard, '', '', '', '', info.source, 'IDcard'])
                    for jwt in info.jwt:
                        writer.writerow([jwt, '', '', '', '', info.source, 'JWT'])
                    for other in info.other:
                        writer.writerow([other, '', '', '', '', info.source, 'Other'])
            
            print(f"结果已导出到: {output_path}")
            
        except Exception as e:
            print(f"CSV导出错误: {e}")
    
    def export_json(self, output_path: str, config: Config):
        try:
            data = {
                'timestamp': datetime.now().isoformat(),
                'js_count': len(self.js_results),
                'url_count': len(self.url_results),
                'domain_count': len(self.domains),
                'js_results': [self.link_to_dict(js) for js in self.js_results],
                'url_results': [self.link_to_dict(url) for url in self.url_results],
                'domains': list(self.domains),
                'sensitive_info': []
            }
            
            for info in self.info_results:
                info_dict = {
                    'source': info.source,
                    'phone': info.phone,
                    'email': info.email,
                    'idcard': info.idcard,
                    'jwt': info.jwt,
                    'other': info.other
                }
                data['sensitive_info'].append(info_dict)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            
            print(f"结果已导出到: {output_path}")
            
        except Exception as e:
            print(f"JSON导出错误: {e}")
    
    def export_html(self, output_path: str, config: Config):
        html_template = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JSHunter Security Analysis Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #333;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ 
            text-align: center; 
            margin-bottom: 40px; 
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 20px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }}
        .header h1 {{ 
            color: #2c3e50;
            font-size: 2.8em;
            margin-bottom: 15px;
            text-shadow: 0 2px 4px rgba(0,0,0,0.1);
            background: linear-gradient(45deg, #3498db, #9b59b6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .header .subtitle {{ 
            color: #7f8c8d;
            font-size: 1.2em;
            margin-bottom: 25px;
            font-weight: 300;
        }}
        .stats {{ 
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }}
        .stat-item {{ 
            background: linear-gradient(135deg, #3498db, #2980b9);
            color: white;
            padding: 20px 30px;
            border-radius: 15px;
            box-shadow: 0 6px 20px rgba(52, 152, 219, 0.3);
            text-align: center;
            min-width: 140px;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        .stat-item:hover {{
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(52, 152, 219, 0.4);
        }}
        .stat-number {{ font-size: 2.2em; font-weight: bold; display: block; margin-bottom: 5px; }}
        .stat-label {{ font-size: 0.95em; opacity: 0.9; }}
        .section {{ 
            margin-bottom: 35px; 
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            overflow: hidden;
        }}
        .section-header {{ 
            background: linear-gradient(135deg, #34495e, #2c3e50);
            color: white;
            padding: 25px 35px;
            font-size: 1.4em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .section-content {{ padding: 0; }}
        .table-container {{ overflow-x: auto; max-height: 600px; }}
        table {{ 
            width: 100%; 
            border-collapse: collapse;
            font-size: 0.95em;
        }}
        th {{ 
            background: linear-gradient(135deg, #ecf0f1, #bdc3c7);
            color: #2c3e50;
            padding: 18px 15px;
            text-align: left;
            font-weight: 600;
            border-bottom: 3px solid #34495e;
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        td {{ 
            padding: 15px;
            border-bottom: 1px solid #ecf0f1;
            vertical-align: top;
        }}
        tr:hover {{ background-color: #f8f9fa; }}
        tr:nth-child(even) {{ background-color: #fdfdfd; }}
        .status-badge {{ 
            padding: 6px 14px;
            border-radius: 25px;
            font-weight: 600;
            font-size: 0.85em;
            display: inline-block;
            text-align: center;
            min-width: 60px;
        }}
        .status-200 {{ 
            background: linear-gradient(135deg, #27ae60, #2ecc71);
            color: white;
            box-shadow: 0 2px 8px rgba(39, 174, 96, 0.3);
        }}
        .status-300 {{ 
            background: linear-gradient(135deg, #f39c12, #e67e22);
            color: white;
            box-shadow: 0 2px 8px rgba(243, 156, 18, 0.3);
        }}
        .status-400 {{ 
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            color: white;
            box-shadow: 0 2px 8px rgba(231, 76, 60, 0.3);
        }}
        .status-default {{ 
            background: linear-gradient(135deg, #95a5a6, #7f8c8d);
            color: white;
            box-shadow: 0 2px 8px rgba(149, 165, 166, 0.3);
        }}
        .url-link {{ 
            color: #3498db;
            text-decoration: none;
            word-break: break-all;
            transition: color 0.3s ease;
            font-weight: 500;
        }}
        .url-link:hover {{ 
            color: #2980b9;
            text-decoration: underline;
        }}
        .domain-grid {{ 
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 20px;
            padding: 25px;
        }}
        .domain-item {{ 
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 20px;
            border-radius: 15px;
            border-left: 5px solid #3498db;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            font-weight: 500;
        }}
        .domain-item:hover {{ 
            transform: translateY(-3px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.15);
            border-left-color: #2980b9;
        }}
        .size-badge {{ 
            background: linear-gradient(135deg, #17a2b8, #138496);
            color: white;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: 600;
        }}
        .type-badge {{ 
            background: linear-gradient(135deg, #6f42c1, #5a32a3);
            color: white;
            padding: 4px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: 600;
        }}
        .sensitive-info {{ 
            background: linear-gradient(135deg, #ffe6e6, #ffcccc);
            border-left: 5px solid #e74c3c;
            padding: 15px;
            margin: 10px 0;
            border-radius: 10px;
        }}
        .warning-icon {{ color: #e74c3c; margin-right: 8px; }}
        .footer {{ 
            text-align: center;
            margin-top: 50px;
            padding: 25px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 15px;
            color: rgba(255, 255, 255, 0.9);
            font-size: 0.95em;
            backdrop-filter: blur(10px);
        }}
        .emoji {{ font-size: 1.2em; margin-right: 8px; }}
        @media (max-width: 768px) {{
            .stats {{ flex-direction: column; align-items: center; }}
            .stat-item {{ margin-bottom: 15px; min-width: 200px; }}
            th, td {{ padding: 12px 8px; font-size: 0.85em; }}
            .domain-grid {{ grid-template-columns: 1fr; }}
            .section-header {{ padding: 20px 25px; font-size: 1.2em; }}
        }}
        .no-data {{ 
            text-align: center; 
            padding: 40px; 
            color: #7f8c8d; 
            font-style: italic; 
        }}
        .search-box {{
            margin: 20px 0;
            padding: 0 25px;
        }}
        .search-input {{
            width: 100%;
            padding: 12px 20px;
            border: 2px solid #bdc3c7;
            border-radius: 25px;
            font-size: 1em;
            transition: border-color 0.3s ease;
        }}
        .search-input:focus {{
            outline: none;
            border-color: #3498db;
        }}
    </style>
    <script>
        function filterTable(inputId, tableId) {{
            const input = document.getElementById(inputId);
            const table = document.getElementById(tableId);
            const filter = input.value.toLowerCase();
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {{
                const cells = rows[i].getElementsByTagName('td');
                let found = false;
                for (let j = 0; j < cells.length; j++) {{
                    if (cells[j].textContent.toLowerCase().includes(filter)) {{
                        found = true;
                        break;
                    }}
                }}
                rows[i].style.display = found ? '' : 'none';
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><span class="emoji">🔍</span>JSHunter Security Analysis</h1>
            <div class="subtitle">JavaScript Files & Security Intelligence Report</div>
            <div class="stats">
                <div class="stat-item">
                    <span class="stat-number">{js_count}</span>
                    <span class="stat-label">JS Files</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number">{url_count}</span>
                    <span class="stat-label">URLs</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number">{domain_count}</span>
                    <span class="stat-label">Domains</span>
                </div>
                <div class="stat-item">
                    <span class="stat-number">{timestamp_short}</span>
                    <span class="stat-label">Generated</span>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <span class="emoji">📄</span>JavaScript Files Analysis ({js_count} files)
            </div>
            <div class="section-content">
                {js_search}
                <div class="table-container">
                    <table id="js-table">
                        <thead>
                            <tr>
                                <th style="width: 45%;">URL</th>
                                <th style="width: 15%;">Status</th>
                                <th style="width: 15%;">Size</th>
                                <th style="width: 25%;">Source</th>
                            </tr>
                        </thead>
                        <tbody>
                            {js_table}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        {url_section}
        
        <div class="section">
            <div class="section-header">
                <span class="emoji">🌐</span>Discovered Domains ({domain_count} domains)
            </div>
            <div class="section-content">
                <div class="domain-grid">
                    {domain_list}
                </div>
            </div>
        </div>
        
        {sensitive_section}
        
        <div class="footer">
            <p><span class="emoji">⚡</span>Generated by JSHunter Security Scanner | {timestamp}</p>
            <p>Powered by Advanced Web Reconnaissance Technology</p>
        </div>
    </div>
</body>
</html>
        '''
        
        try:
            js_rows = []
            for js in self.js_results:
                status_badge = self.get_status_badge(js.status)
                size_badge = f'<span class="size-badge">{js.size}</span>' if js.size else ''
                
                js_rows.append(
                    f'<tr>'
                    f'<td><a href="{js.url}" target="_blank" class="url-link">{js.url}</a></td>'
                    f'<td>{status_badge}</td>'
                    f'<td>{size_badge}</td>'
                    f'<td><a href="{js.source}" target="_blank" class="url-link">{js.source}</a></td>'
                    f'</tr>'
                )
            
            url_section = ''
            if self.url_results:
                url_rows = []
                for url in self.url_results:
                    status_badge = self.get_status_badge(url.status)
                    size_badge = f'<span class="size-badge">{url.size}</span>' if url.size else ''
                    
                    url_rows.append(
                        f'<tr>'
                        f'<td><a href="{url.url}" target="_blank" class="url-link">{url.url}</a></td>'
                        f'<td>{status_badge}</td>'
                        f'<td>{size_badge}</td>'
                        f'<td>{url.title}</td>'
                        f'<td><a href="{url.source}" target="_blank" class="url-link">{url.source}</a></td>'
                        f'</tr>'
                    )
                
                url_search = '''
                <div class="search-box">
                    <input type="text" id="url-search" class="search-input" placeholder="🔍 Search URLs..." 
                           onkeyup="filterTable('url-search', 'url-table')">
                </div>
                '''
                
                url_section = f'''
                <div class="section">
                    <div class="section-header">
                        <span class="emoji">🔗</span>URL Links Analysis ({len(self.url_results)} URLs)
                    </div>
                    <div class="section-content">
                        {url_search}
                        <div class="table-container">
                            <table id="url-table">
                                <thead>
                                    <tr>
                                        <th style="width: 40%;">URL</th>
                                        <th style="width: 12%;">Status</th>
                                        <th style="width: 12%;">Size</th>
                                        <th style="width: 20%;">Title</th>
                                        <th style="width: 16%;">Source</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {''.join(url_rows)}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                '''
            
            domain_items = []
            for domain in sorted(self.domains):
                domain_items.append(f'<div class="domain-item">{domain}</div>')
            
            sensitive_section = ''
            if self.info_results:
                sensitive_items = []
                for info in self.info_results:
                    if info.has_data():
                        items = []
                        if info.phone: items.extend([f"📱 {p}" for p in info.phone])
                        if info.email: items.extend([f"📧 {e}" for e in info.email])
                        if info.idcard: items.extend([f"🆔 {i}" for i in info.idcard])
                        if info.jwt: items.extend([f"🔑 {j[:50]}..." for j in info.jwt])
                        if info.other: items.extend([f"⚠️ {o}" for o in info.other])
                        
                        for item in items:
                            sensitive_items.append(
                                f'<div class="sensitive-info">'
                                f'<span class="warning-icon">⚠️</span>{item}'
                                f'<br><small>Source: {info.source}</small>'
                                f'</div>'
                            )
                
                if sensitive_items:
                    sensitive_section = f'''
                    <div class="section">
                        <div class="section-header">
                            <span class="emoji">🚨</span>Sensitive Information Detected ({len(sensitive_items)} items)
                        </div>
                        <div class="section-content" style="padding: 25px;">
                            {''.join(sensitive_items)}
                        </div>
                    </div>
                    '''
            
            js_search = '''
            <div class="search-box">
                <input type="text" id="js-search" class="search-input" placeholder="🔍 Search JavaScript files..." 
                       onkeyup="filterTable('js-search', 'js-table')">
            </div>
            '''
            
            timestamp = datetime.now()
            timestamp_full = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            timestamp_short = timestamp.strftime('%m/%d')
            
            html_content = html_template.format(
                timestamp=timestamp_full,
                timestamp_short=timestamp_short,
                js_count=len(self.js_results),
                url_count=len(self.url_results),
                domain_count=len(self.domains),
                js_search=js_search,
                js_table=''.join(js_rows) if js_rows else '<tr><td colspan="4" class="no-data">No JavaScript files found</td></tr>',
                url_section=url_section,
                domain_list=''.join(domain_items) if domain_items else '<div class="no-data">No domains discovered</div>',
                sensitive_section=sensitive_section
            )
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print("HTML report generated successfully")
            
        except Exception as e:
            print(f"HTML export error: {e}")
    
    def get_status_class(self, status: str) -> str:
        if not status:
            return ''
        if status.startswith('2'):
            return 'status-200'
        elif status.startswith('3'):
            return 'status-300'
        else:
            return 'status-400'
    
    def get_status_badge(self, status: str) -> str:
        if not status:
            return '<span class="status-badge status-default">N/A</span>'
        
        if status.startswith('2'):
            return f'<span class="status-badge status-200">{status}</span>'
        elif status.startswith('3'):
            return f'<span class="status-badge status-300">{status}</span>'
        else:
            return f'<span class="status-badge status-400">{status}</span>'
    
    def get_console_status_indicator(self, status: str) -> str:
        if not status:
            return "\033[90m[?]\033[0m"
        
        if status.startswith('2'):
            return "\033[92m[OK]\033[0m"
        elif status.startswith('3'):
            return "\033[93m[RD]\033[0m"
        elif status.startswith('4'):
            return "\033[91m[ER]\033[0m"
        elif status.startswith('5'):
            return "\033[91m[!!]\033[0m"
        else:
            return "\033[90m[??]\033[0m"
    
    def print_sensitive_info_enhanced(self):
        if not self.info_results:
            return
        
        print(f"\n\033[96m[SEC] Sensitive Information Analysis:\033[0m")
        
        all_sensitive = {
            '[PHONE] Phone Numbers': [],
            '[EMAIL] Email Addresses': [],
            '[ID] ID Cards': [],
            '[JWT] JWT Tokens': [],
            '[GAPI] Google API Keys': [],
            '[AWS] AWS Keys': [],
            '[BEAR] Bearer Tokens': [],
            '[OAUTH] OAuth Tokens': [],
            '[SSH] SSH Keys': [],
            '[GIT] GitHub Tokens': [],
            '[SLACK] Slack Tokens': [],
            '[OTHER] Other Secrets': []
        }
        
        for info in self.info_results:
            if info.phone:
                for phone in info.phone:
                    all_sensitive['[PHONE] Phone Numbers'].append((phone, info.source))
            if info.email:
                for email in info.email:
                    all_sensitive['[EMAIL] Email Addresses'].append((email, info.source))
            if info.idcard:
                for idcard in info.idcard:
                    all_sensitive['[ID] ID Cards'].append((idcard, info.source))
            if info.jwt:
                for jwt in info.jwt:
                    all_sensitive['[JWT] JWT Tokens'].append((jwt[:50] + "...", info.source))
            if info.google_api:
                for key in info.google_api:
                    all_sensitive['[GAPI] Google API Keys'].append((key[:30] + "...", info.source))
            if info.aws_key:
                for key in info.aws_key:
                    all_sensitive['[AWS] AWS Keys'].append((key[:30] + "...", info.source))
            if info.bearer_token:
                for token in info.bearer_token:
                    all_sensitive['[BEAR] Bearer Tokens'].append((token[:40] + "...", info.source))
            if info.oauth_token:
                for token in info.oauth_token:
                    all_sensitive['[OAUTH] OAuth Tokens'].append((token[:40] + "...", info.source))
            if info.ssh_key:
                for key in info.ssh_key:
                    all_sensitive['[SSH] SSH Keys'].append((key[:50] + "...", info.source))
            if info.github_token:
                for token in info.github_token:
                    all_sensitive['[GIT] GitHub Tokens'].append((token[:30] + "...", info.source))
            if info.slack_token:
                for token in info.slack_token:
                    all_sensitive['[SLACK] Slack Tokens'].append((token[:30] + "...", info.source))
            if info.other:
                for other in info.other:
                    all_sensitive['[OTHER] Other Secrets'].append((other[:60] + "...", info.source))
        
        total_sensitive = 0
        for category, items in all_sensitive.items():
            if items:
                print(f"\n   \033[91m{category} ({len(items)}):\033[0m")
                for i, (item, source) in enumerate(items, 1):
                    total_sensitive += 1
                    print(f"      \033[94m{i}.\033[0m \033[93m{item}\033[0m")
                    print(f"         |-- \033[90mSource: {source}\033[0m")
        
        if total_sensitive == 0:
            print(f"   \033[90mNo sensitive information detected\033[0m")
        else:
            print(f"\n   \033[91m[!] Total sensitive items found: {total_sensitive}\033[0m")
    
    def link_to_dict(self, link: Link) -> dict:
        return {
            'url': link.url,
            'source': link.source or '',
            'status': link.status or '',
            'size': link.size or '',
            'title': (link.title or '').replace('\n', ' ').replace('\r', ' '),
            'redirect': link.redirect or ''
        }
    
    def generate_auto_report(self, config: Config) -> Optional[str]:
        try:
            results_dir = "results"
            if not os.path.exists(results_dir):
                os.makedirs(results_dir)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            target_name = "unknown"
            if hasattr(config, 'target_url') and config.target_url:
                try:
                    parsed = urlparse(config.target_url)
                    domain = parsed.netloc
                    if domain:
                        target_name = domain.replace(':', '_').replace('/', '_')
                except:
                    pass
            
            features = []
            if config.enable_url_scan:
                features.append("urls")
            if config.enable_api_scan:
                features.append("api")
            if config.enable_secret_scan:
                features.append("secrets")
            
            feature_suffix = "_" + "-".join(features) if features else "_js"
            
            filename = f"JSHunter_{target_name}_{timestamp}{feature_suffix}.html"
            report_path = os.path.join(results_dir, filename)
            
            self.export_html(report_path, config)
            
            return report_path
            
        except Exception as e:
            print(f"Auto report generation failed: {e}")
            return None