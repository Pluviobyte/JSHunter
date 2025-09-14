import re
import multiprocessing
from typing import List, Dict, Optional
from anti_detection import AntiDetectionHelper, SmartDefaults

class ScanMode:
    QUICK = "quick"      # 只扫描主页
    STANDARD = "standard" # 当前默认行为
    DEEP = "deep"        # 深度递归扫描

class Config:
    def __init__(self,
                 threads: int = None,
                 cookie: Optional[str] = None,
                 proxy: Optional[str] = None,
                 enable_url_scan: bool = False,
                 enable_api_scan: bool = False,
                 enable_secret_scan: bool = False,
                 scan_mode: str = ScanMode.STANDARD,
                 quick_timeout: int = 10,
                 max_depth: int = 1):
        
        self.anti_detection = AntiDetectionHelper()

        # 扫描模式设置
        self.scan_mode = scan_mode
        self.quick_timeout = quick_timeout
        self.max_depth = max_depth

        # 根据扫描模式调整参数
        if scan_mode == ScanMode.QUICK:
            self.threads = min(threads or 5, 5)  # 快速模式限制线程数
            self.timeout = quick_timeout
            self.max_urls = 50  # 限制最大URL数量
            self.url_steps = 0  # 不递归
            self.js_steps = 0   # 不递归
        else:
            self.threads = threads or SmartDefaults.get_optimal_threads()
            self.timeout = SmartDefaults.get_optimal_timeout()
            self.max_urls = SmartDefaults.get_optimal_max_urls()
            self.url_steps = 1 if scan_mode == ScanMode.STANDARD else max_depth
            self.js_steps = 2 if scan_mode == ScanMode.STANDARD else max_depth + 1

        self.cookie = cookie
        self.proxy = proxy

        self.enable_url_scan = enable_url_scan
        self.enable_api_scan = enable_api_scan
        self.enable_secret_scan = enable_secret_scan
        
        self.setup_regex_patterns()
    
    def get_headers(self, custom_headers: Dict[str, str] = None) -> Dict[str, str]:
        headers = {}
        if self.cookie:
            headers['Cookie'] = self.cookie
        if custom_headers:
            headers.update(custom_headers)
        return self.anti_detection.get_headers(headers)
    
    def get_random_delay(self) -> float:
        return self.anti_detection.get_random_delay()
    
    
    def setup_regex_patterns(self):
        self.linkfinder_patterns = [
            r'''(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,}))(?:"|')''',
            r'''(?:"|')(((?:/|\.\.?/)[^"'><,;|\*()\s]{1,}))(?:"|')''',
            r'''(?:"|')(([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/.]{1,}))(?:"|')''',
            r'''(?:"|')([a-zA-Z0-9_\-/.]{1,})(?:"|')'''
        ]
        
        self.modern_js_patterns = [
            r'<script[^>]+src=[\'\"]\s*([^\'\"]+\.js[^\'\"]*)',
            r'(?:import|require)\s*\([\'\"](([^\'\"]+\.js[^\'\"]*)[\'\"]\)',
            r'from\s+[\'\"](([^\'\"]+\.js[^\'\"]*)[\'\"]\)',
            r'\.src\s*=\s*[\'\"](([^\'\"]+\.js[^\'\"]*)[\'\"]\)',
            r'loadScript[^\'\"]*[\'\"](([^\'\"]+\.js[^\'\"]*)[\'\"]\)',
            r'chunk[^\'\"]*[\'\"](([^\'\"]*\.js[^\'\"]*)[\'\"]\)',
            r'__webpack[^\'\"]*[\'\"](([^\'\"]+\.js[^\'\"]*)[\'\"]\)',
            r'System\.import[^\'\"]*[\'\"](([^\'\"]+\.js[^\'\"]*)[\'\"]\)',
            r'(?:var|let|const)\s+\w+\s*=\s*[\'\"](([^\'\"]*\.js[^\'\"]*)[\'\"]\)'
        ]
        
        self.js_patterns = [
            r'(https?:[-a-zA-Z0-9（）@:%_\+.~#?&//=]{2,250}?[-a-zA-Z0-9（）@:%_\+.~#?&//=]{3}\.js)',
            r'["\'\`]\s{0,6}(/{0,1}[-a-zA-Z0-9（）@:%_\+.~#?&//=]{2,250}?[-a-zA-Z0-9（）@:%_\+.~#?&//=]{3}\.js)',
            r'=\s{0,6}["\',\`]{0,1}\s{0,6}(/{0,1}[-a-zA-Z0-9（）@:%_\+.~#?&//=]{2,250}?[-a-zA-Z0-9（）@:%_\+.~#?&//=]{3}\.js)',
        ]
        
        self.api_patterns = [
            r'["\'\`]\s{0,6}((?:https?://)?[^"\']*?/api/[^"\'?\s]*(?:\?[^"\']*)?)',
            r'["\'\`]\s{0,6}((?:https?://)?[^"\']*?/v\d+/[^"\'?\s]*(?:\?[^"\']*)?)',
            r'["\'\`]\s{0,6}((?:https?://)?[^"\']*?/rest/[^"\'?\s]*(?:\?[^"\']*)?)',
            
            r'["\'\`]\s{0,6}((?:https?://)?[^"\']*?/graphql[^"\'?\s]*(?:\?[^"\']*)?)',
            
            r'["\'\`]\s{0,6}(/?(?:api|v\d+|rest|graphql|service|endpoint)/[^"\'?\s]*(?:\?[^"\']*)?)',
            
            r'(?:url|endpoint|path)\s*[:=]\s*["\']([^"\']+)["\']',
            r'(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']',
            
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
            
            r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']',
            
            r'["\'\`]\s{0,6}(/[a-zA-Z0-9._\-/]*(?:\?[^"\']*)?)',
            
            r'(?:href|action)\s*=\s*["\']([^"\']+)["\']',
        ]
        
        self.api_method_patterns = {
            'get': r'(?:GET|get)\s*[:\(]',
            'post': r'(?:POST|post)\s*[:\(]',
            'put': r'(?:PUT|put)\s*[:\(]',
            'delete': r'(?:DELETE|delete)\s*[:\(]',
            'patch': r'(?:PATCH|patch)\s*[:\(]',
            'head': r'(?:HEAD|head)\s*[:\(]',
            'options': r'(?:OPTIONS|options)\s*[:\(]',
        }
        
        self.api_framework_patterns = {
            'express': r'express|app\.(?:get|post|put|delete)',
            'koa': r'koa|ctx\.body|ctx\.request',
            'fastapi': r'fastapi|@app\.(?:get|post|put|delete)',
            'flask': r'flask|@app\.route',
            'django': r'django|urlpatterns|path\(',
            'spring': r'@RestController|@RequestMapping|@GetMapping',
            'laravel': r'Route::|Illuminate\\',
            'rails': r'Rails\.application|ActionController',
            'asp_net': r'ApiController|HttpGet|HttpPost',
            'gin': r'gin\.Default|router\.(?:GET|POST)',
            'echo': r'echo\.New|e\.(?:GET|POST)',
            'chi': r'chi\.NewRouter|r\.(?:Get|Post)',
        }
        
        self.sensitive_api_patterns = [
            r'/admin/', r'/manager/', r'/console/', r'/dashboard/',
            r'/config/', r'/settings/', r'/user/', r'/users/',
            r'/account/', r'/profile/', r'/auth/', r'/login/',
            r'/logout/', r'/register/', r'/password/', r'/token/',
            r'/key/', r'/secret/', r'/private/', r'/internal/',
            r'/debug/', r'/test/', r'/dev/', r'/staging/',
            r'/backup/', r'/upload/', r'/download/', r'/file/',
        ]
        
        self.api_filter_patterns = [
            r'\.css\??', r'\.js\??', r'\.jpeg?\??', r'\.png\??',
            r'\.gif\??', r'\.ico\??', r'\.svg\??', r'\.woff2?\??',
            r'\.ttf\??', r'\.eot\??', r'javascript:', r'mailto:',
            r'tel:', r'data:', r'#[^/]', r'/static/', r'/assets/',
            r'/public/', r'/images/', r'/img/', r'/css/', r'/js/', r'/fonts/',
        ]
        
        self.url_patterns = [
            r'["\'\`]\s{0,6}(https?:[-a-zA-Z0-9()@:%_\+.~#?&//={}]{2,250}?)\s{0,6}["\'\`]',
            r'=\s{0,6}(https?:[-a-zA-Z0-9()@:%_\+.~#?&//={}]{2,250})',
            r'["\'\`]\s{0,6}([#,.]{0,2}/[-a-zA-Z0-9()@:%_\+.~#?&//={}]{2,250}?)\s{0,6}["\'\`]',
            r'"([-a-zA-Z0-9()@:%_\+.~#?&//={}]+?[/]{1}[-a-zA-Z0-9()@:%_\+.~#?&//={}]+?)"',
            r'href\s{0,6}=\s{0,6}["\'\`]{0,1}\s{0,6}([-a-zA-Z0-9()@:%_\+.~#?&//={}]{2,250})|action\s{0,6}=\s{0,6}["\'\`]{0,1}\s{0,6}([-a-zA-Z0-9()@:%_\+.~#?&//={}]{2,250})',
        ]
        
        self.js_filter_patterns = [
            r'www\.w3\.org',
            r'example\.com',
        ]
        
        self.url_filter_patterns = [
            r'\.js\?|\.css\?|\.jpeg\?|\.jpg\?|\.png\?|\.gif\?|www\.w3\.org|example\.com|\<|\>|\{|\}|\[|\]|\||\^|;|/js/|\.src|\.replace|\.url|\.att|\.href|location\.href|javascript:|location:|application/x-www-form-urlencoded|\.createObject|:location|\.path|\*#__PURE__\*|\*\$0\*|\n',
            r'.*\.js$|.*\.css$|.*\.scss$|.*,$|.*\.jpeg$|.*\.jpg$|.*\.png$|.*\.gif$|.*\.ico$|.*\.svg$|.*\.vue$|.*\.ts$',
        ]
        
        self.info_patterns = {
            'phone': [r'[\'\"](1(3([0-35-9]\d|4[1-8])|4[14-9]\d|5([\d]\d|7[1-79])|66\d|7[2-35-8]\d|8\d{2}|9[89]\d)\d{7})[\'\"]'],
            'email': [r'[\'\"]([\w!#$%&\'*+/=?^_`{|}~-]+(?:\.[\w!#$%&\'*+/=?^_`{|}~-]+)*@(?:[\w](?:[\w-]*[\w])?\.)+[\w](?:[\w-]*[\w])?)[\'\"]'],
            'idcard': [r'[\'\"]((\\d{8}(0\\d|10|11|12)([0-2]\\d|30|31)\\d{3}$)|(\\d{6}(18|19|20)\\d{2}(0[1-9]|10|11|12)([0-2]\\d|30|31)\\d{3}(\\d|X|x)))[\'\"]'],
            'jwt': [r'[\'\"](ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|ey[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,})[\'\"]'],
            'google_api': [r'AIza[0-9A-Za-z\-_]{35}'],
            'aws_key': [r'AKIA[0-9A-Z]{16}'],
            'bearer_token': [r'(?i)bearer\s+[a-zA-Z0-9_\-\.=:_\+\/]{20,100}'],
            'oauth_token': [r'(?i)oauth[_-]?token[\'\""]?\s*[:=]\s*[\'\""]?[a-zA-Z0-9_\-]{32,}'],
            'ssh_key': [r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----'],
            'github_token': [r'gh[pousr]_[A-Za-z0-9_]{36,255}'],
            'slack_token': [r'xox[baprs]-[0-9a-zA-Z]{10,48}'],
            'other': [r'(access.{0,1}key|access.{0,1}Key|access.{0,1}Id|access.{0,1}id|.{0,5}密码|.{0,5}账号|默认.{0,5}|加密|解密|password:.{0,10}|username:.{0,10})'],
        }
        
        self.js_fuzz_paths = [
            "login.js", "app.js", "main.js", "config.js", "admin.js",
            "info.js", "open.js", "user.js", "input.js", "list.js", "upload.js"
        ]