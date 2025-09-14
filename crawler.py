
import re
import requests
import threading
import time
import random
from urllib.parse import urljoin, urlparse, unquote
from typing import List, Set, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import gzip
from io import BytesIO

from config import Config
from result import ResultManager, Link, SensitiveInfo

class Crawler:
    def __init__(self, config: Config, result_manager: ResultManager):
        self.config = config
        self.result_manager = result_manager
        self.visited_urls: Set[str] = set()
        self.lock = threading.Lock()
        self.progress = 0
        
        self.session = requests.Session()
        
        headers = config.get_headers()
        self.session.headers.update(headers)
        
        if config.proxy:
            self.session.proxies.update({
                'http': config.proxy,
                'https': config.proxy
            })
        
        self.session.timeout = config.timeout
        self.session.verify = False
        
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def crawl_single(self, url: str):
        if hasattr(self.config, 'scan_mode') and self.config.scan_mode == "quick":
            print(f"⚡ 快速扫描模式: {url}")
            self.quick_scan(url)
        else:
            print(f"Starting crawl: {url}")
            self.spider(url, 1)
            self.validate_urls()
        print("Crawl completed!")

    def quick_scan(self, url: str):
        """快速扫描模式：仅扫描主页JS文件"""
        import time
        start_time = time.time()

        response = self.fetch_url(url)
        if not response:
            print(f"  ❌ 无法访问页面: {url}")
            return

        # 获取响应文本内容
        content = getattr(response, 'decoded_text', response.text)

        # 获取URL的组成部分
        from urllib.parse import urlparse
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        path = parsed_url.path if parsed_url.path else "/"

        # 提取JS文件
        self.extract_js(content, base_url, path, url, 0)

        # 如果启用了其他扫描，也对主页进行分析
        if self.config.enable_url_scan:
            self.extract_urls(content, base_url, path, url, 0)

        if self.config.enable_secret_scan:
            self.extract_sensitive_info(content, url)

        elapsed = time.time() - start_time
        print(f"  ✅ 快速扫描完成 ({elapsed:.2f}s)")

    def fetch_url(self, url: str):
        """获取URL内容，支持超时控制"""
        try:
            self.session.headers.update(self.config.get_headers())
            response = self.session.get(url, timeout=self.config.timeout)

            content = response.content
            if response.headers.get('Content-Encoding') == 'gzip':
                try:
                    content = gzip.decompress(content)
                except:
                    pass

            try:
                text = content.decode('utf-8', errors='ignore')
            except:
                text = content.decode('latin-1', errors='ignore')

            # 将text内容添加为属性
            response.decoded_text = text
            return response

        except requests.exceptions.Timeout:
            print(f"  ⚠️ 请求超时: {url}")
            return None
        except Exception as e:
            print(f"  ❌ 请求失败: {e}")
            return None

    def crawl_batch(self, file_path: str):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            print(f"Found {len(urls)} URLs")
            
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                futures = []
                for i, url in enumerate(urls):
                    if i >= self.config.max_urls:
                        break
                    future = executor.submit(self.spider, url, 1)
                    futures.append(future)
                
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"Crawl error: {e}")
            
            self.validate_urls()
            print("Batch crawl completed!")
            
        except FileNotFoundError:
            print(f"Error: File not found {file_path}")
        except Exception as e:
            print(f"File read error: {e}")
    
    def spider(self, url: str, depth: int):
        with self.lock:
            self.progress += 1
            print(f"\rProgress: {self.progress}", end='', flush=True)
        
        url = unquote(url)
        
        if url in self.visited_urls:
            return
        
        
        self.visited_urls.add(url)
        
        try:
            delay = self.config.get_random_delay()
            time.sleep(delay)
            
            self.session.headers.update(self.config.get_headers())

            response = self.session.get(url, timeout=self.config.timeout)
            
            content = response.content
            if response.headers.get('Content-Encoding') == 'gzip':
                try:
                    content = gzip.decompress(content)
                except:
                    pass
            
            try:
                text = content.decode('utf-8', errors='ignore')
            except:
                text = content.decode('gbk', errors='ignore')
            
            actual_url = response.url
            parsed_url = urlparse(actual_url)
            scheme = parsed_url.scheme
            host = parsed_url.netloc
            path = parsed_url.path
            
            base_match = re.search(r'<base[^>]*href\s*=\s*["\']([^"\']+)["\']', text, re.IGNORECASE)
            if base_match:
                base_url = base_match.group(1)
                base_parsed = urlparse(base_url)
                if base_parsed.netloc:
                    scheme = base_parsed.scheme
                    host = base_parsed.netloc
                    path = base_parsed.path
            
            base_url = f"{scheme}://{host}"
            
            self.extract_js(text, base_url, path, url, depth)
            
            if self.config.enable_api_scan:
                self.extract_api_endpoints(text, base_url, path, url)
            
            if self.config.enable_url_scan:
                self.extract_urls(text, base_url, path, url, depth)
            
            if self.config.enable_secret_scan:
                self.extract_sensitive_info(text, url)
            
        except requests.RequestException as e:
            print(f"\nRequest error {url}: {e}")
        except Exception as e:
            print(f"\nProcess error {url}: {e}")
    
    def extract_js(self, content: str, base_url: str, path: str, source: str, depth: int):
        js_urls = set()

        # 快速模式：如果来源是打包文件，跳过深度提取
        if hasattr(self.config, 'scan_mode') and self.config.scan_mode == "quick":
            if self.is_bundled_file(source):
                return

        for i, pattern in enumerate(self.config.linkfinder_patterns, 1):
            try:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                for match in matches:
                    if isinstance(match, tuple):
                        js_url = match[0] if match[0] else (match[1] if len(match) > 1 else "")
                    else:
                        js_url = match

                    if js_url and self.is_js_file(js_url) and not self.is_internal_module_path(js_url):
                        js_urls.add(js_url)
            except re.error:
                continue
        
        for pattern in self.config.modern_js_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                for match in matches:
                    if isinstance(match, tuple):
                        js_url = next((m for m in match if m), "")
                    else:
                        js_url = match
                    
                    if js_url and self.is_js_file(js_url):
                        js_urls.add(js_url)
            except re.error:
                continue
        
        for pattern in self.config.js_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    js_url = match[0] if match[0] else (match[1] if len(match) > 1 else '')
                else:
                    js_url = match
                
                if js_url and self.is_js_file(js_url):
                    js_urls.add(js_url)
        
        for js_url in js_urls:
            if self.should_filter_js(js_url):
                continue
            
            full_js_url = self.build_full_url(js_url, base_url, path)
            if not full_js_url:
                continue
            
            if self.result_manager.add_js(full_js_url, source):
                if depth <= self.config.js_steps:
                    self.spider(full_js_url, depth + 1)
    
    def is_js_file(self, url: str) -> bool:
        if not url:
            return False
        return '.js' in url.lower() and not url.startswith('data:')

    def is_bundled_file(self, url: str) -> bool:
        """检测是否为打包文件（应跳过内容解析）"""
        if not url:
            return False

        # 检测Vite/Webpack打包文件特征
        bundled_patterns = [
            r'/static/js/index-[a-f0-9]{8}\.js',  # index-hash.js
            r'/static/js/index-legacy-[a-f0-9]{8}\.js',  # index-legacy-hash.js
            r'/js/app\.[a-f0-9]{8}\.js',  # app.hash.js
            r'/js/vendor\.[a-f0-9]{8}\.js',  # vendor.hash.js
            r'/js/chunk-[a-f0-9]+\.js',  # chunk-hash.js
        ]

        for pattern in bundled_patterns:
            if re.search(pattern, url):
                return True
        return False

    def is_internal_module_path(self, js_url: str) -> bool:
        """检测是否为内部模块路径（不是真实的JS文件URL）"""
        if not js_url:
            return False

        # 过滤相对路径引用（这些通常是打包文件内的模块引用）
        if js_url.startswith('./') or js_url.startswith('../'):
            return True

        # 过滤Node.js模块引用
        if js_url.startswith('@/') or js_url.startswith('~/'):
            return True

        # 过滤纯模块名（没有完整URL）
        if not js_url.startswith('http') and not js_url.startswith('/') and '/' not in js_url:
            return True

        return False

    def extract_api_endpoints(self, content: str, base_url: str, path: str, source: str):
        api_urls = set()
        
        for pattern in self.config.api_patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                for match in matches:
                    if isinstance(match, tuple):
                        api_url = next((m for m in match if m), "")
                    else:
                        api_url = match
                    
                    if api_url and self.is_api_endpoint(api_url):
                        api_urls.add(api_url)
            except re.error:
                continue
        
        detected_frameworks = self.detect_api_frameworks(content)
        if detected_frameworks:
            print(f"\n[API Framework] Detected: {', '.join(detected_frameworks)} in {source}")
        
        for api_url in api_urls:
            if self.is_static_resource(api_url):
                continue
                
            full_api_url = self.build_full_url(api_url, base_url, path)
            if full_api_url:
                is_sensitive = self.is_sensitive_api(full_api_url)
                self.result_manager.add_url(full_api_url, source, is_api=True)
                
                if is_sensitive:
                    print(f"\n[SENSITIVE API] {full_api_url}")
    
    def detect_api_frameworks(self, content: str) -> List[str]:
        frameworks = []
        for framework, pattern in self.config.api_framework_patterns.items():
            try:
                if re.search(pattern, content, re.IGNORECASE):
                    frameworks.append(framework)
            except re.error:
                continue
        return frameworks
    
    def is_sensitive_api(self, url: str) -> bool:
        url_lower = url.lower()
        for pattern in self.config.sensitive_api_patterns:
            try:
                if re.search(pattern, url_lower):
                    return True
            except re.error:
                continue
        return False
    
    def is_static_resource(self, url: str) -> bool:
        url_lower = url.lower()
        for pattern in self.config.api_filter_patterns:
            try:
                if re.search(pattern, url_lower):
                    return True
            except re.error:
                continue
        return False
    
    def is_api_endpoint(self, url: str) -> bool:
        if not url:
            return False
        url_lower = url.lower()
        
        api_keywords = [
            '/api/', '/v1/', '/v2/', '/v3/', '/v4/', '/rest/', 
            '/graphql', '/service/', '/endpoint/', 'api.', 
            '.json', '/json/', '/xml/', '/rpc/'
        ]
        
        has_api_keyword = any(keyword in url_lower for keyword in api_keywords)
        
        if self.is_static_resource(url):
            return False
            
        if has_api_keyword:
            return True
            
        if url.startswith('/') and len(url) > 1:
            static_page_patterns = ['.html', '.htm', '.php', '.jsp', '.asp']
            if any(pattern in url_lower for pattern in static_page_patterns):
                return False
            return True
            
        return False
    
    def extract_urls(self, content: str, base_url: str, path: str, source: str, depth: int):
        for pattern in self.config.url_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    url = next((m for m in match if m), '')
                else:
                    url = match
                
                if not url:
                    continue
                
                if self.should_filter_url(url):
                    continue

                full_url = self.build_full_url(url, base_url, path, is_js_source=source.endswith('.js'))
                if not full_url:
                    continue

                if self.result_manager.add_url(full_url, source):
                    if depth <= self.config.url_steps:
                        self.spider(full_url, depth + 1)
    
    def extract_sensitive_info(self, content: str, source: str):
        info = SensitiveInfo(source=source)
        
        for info_type, patterns in self.config.info_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for match in matches:
                    if isinstance(match, tuple):
                        value = match[0] if match[0] else match[1]
                    else:
                        value = match
                    
                    if value:
                        getattr(info, info_type).append(value)
        
        if info.has_data():
            self.result_manager.add_info(info)
    
    def should_filter_js(self, js_url: str) -> bool:
        for pattern in self.config.js_filter_patterns:
            if re.search(pattern, js_url):
                return True
        return False
    
    def should_filter_url(self, url: str) -> bool:
        for pattern in self.config.url_filter_patterns:
            if re.search(pattern, url):
                return True
        return False
    
    def build_full_url(self, url: str, base_url: str, path: str, is_js_source: bool = False) -> Optional[str]:
        if url.startswith(('http://', 'https://')):
            return url
        elif url.startswith('//'):
            return f"{urlparse(base_url).scheme}:{url}"
        elif url.startswith('/'):
            return f"{base_url}{url}"
        else:
            
            if is_js_source:
                js_path = self.result_manager.get_js_path(base_url + path)
                if js_path:
                    if js_path.endswith('/'):
                        return f"{js_path}{url}"
                    else:
                        return f"{js_path}/{url}"
            
            if path.endswith('/'):
                return f"{base_url}{path}{url}"
            else:
                dir_path = '/'.join(path.split('/')[:-1])
                if dir_path:
                    return f"{base_url}{dir_path}/{url}"
                else:
                    return f"{base_url}/{url}"
        
        return None
    
    def validate_urls(self):
        return
        
        print("\nStarting URL status validation...")
        
        all_urls = self.result_manager.get_all_urls()
        total = len(all_urls)
        
        if total == 0:
            return
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self.check_url_status, url): url for url in all_urls}
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                print(f"\rValidation progress: {completed}/{total} ({completed/total*100:.1f}%)", end='', flush=True)
                
                try:
                    url, status, size, title, redirect = future.result()
                    if status:
                        if self.should_show_status(status):
                            self.result_manager.update_url_status(url, status, size, title, redirect)
                except Exception as e:
                    print(f"\nStatus check error: {e}")
        
        print("\nURL status validation completed!")
    
    def check_url_status(self, url: str) -> tuple:
        try:
            response = self.session.head(url, allow_redirects=True, timeout=self.config.timeout)
            status = str(response.status_code)
            size = response.headers.get('Content-Length', '0')
            redirect = response.url if response.url != url else ''
            
            title = ''
            if response.status_code == 200:
                try:
                    resp = self.session.get(url, timeout=self.config.timeout)
                    soup = BeautifulSoup(resp.content, 'html.parser')
                    title_tag = soup.find('title')
                    if title_tag:
                        title = title_tag.get_text().strip()[:100]
                except:
                    pass
            
            return url, status, size, title, redirect
            
        except requests.RequestException:
            return url, None, None, None, None
    
    def should_show_status(self, status: str) -> bool:
        return False