
import random
import time
import multiprocessing
from typing import Dict, List

class AntiDetectionHelper:
    
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        
        self.base_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none'
        }
    
    def get_random_ua(self) -> str:
        return random.choice(self.user_agents)
    
    def get_random_delay(self, min_delay: float = 0.5, max_delay: float = 2.0) -> float:
        return random.uniform(min_delay, max_delay)
    
    def get_headers(self, custom_headers: Dict[str, str] = None) -> Dict[str, str]:
        headers = self.base_headers.copy()
        headers['User-Agent'] = self.get_random_ua()
        
        if custom_headers:
            headers.update(custom_headers)
        
        return headers
    
    def sleep_random(self, min_delay: float = 0.5, max_delay: float = 2.0):
        delay = self.get_random_delay(min_delay, max_delay)
        time.sleep(delay)

class SmartDefaults:
    
    @staticmethod
    def get_optimal_threads() -> int:
        cpu_count = multiprocessing.cpu_count()
        optimal = min(100, max(10, cpu_count * 8))
        return optimal
    
    @staticmethod
    def get_optimal_timeout() -> int:
        return 5
    
    @staticmethod
    def get_optimal_max_urls() -> int:
        return 50000