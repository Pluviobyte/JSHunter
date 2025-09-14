__version__ = "1.0.0"
__author__ = "JSHunter Team"
__license__ = "MIT"
__description__ = "Advanced JavaScript Discovery Tool for Security Assessment"
__url__ = "https://github.com/your-username/JSHunter"

import argparse
import sys
import os
import codecs

if sys.platform.startswith('win'):
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    try:
        os.system('chcp 65001 >nul 2>&1')
    except:
        pass
    try:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except:
        pass

from crawler import Crawler
from config import Config, ScanMode
from utils import print_banner, validate_url
from result import ResultManager

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='JSHunter - Advanced JavaScript Discovery Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例用法:
  python jshunter.py -u https://example.com                    
  python jshunter.py -u https://example.com --scan-all         
  python jshunter.py -f urls.txt --scan-api                    
  python jshunter.py -u https://example.com -c "session=abc"   
  python jshunter.py -u https://example.com -x http://127.0.0.1:8080  
        '''
    )
    parser.add_argument('-u', '--url', help='目标URL')
    parser.add_argument('-f', '--file', help='批量url抓取,需指定url文本路径')
    parser.add_argument('-o', '--output', help='结果导出文件路径（支持csv、json、html）')
    parser.add_argument('-c', '--cookie', help='设置Cookie')
    parser.add_argument('-x', '--proxy', help='设置代理，格式: http://127.0.0.1:8080')
    parser.add_argument('-t', '--threads', type=int, help='设置线程数（默认：智能CPU自适应）')
    
    parser.add_argument('--scan-urls', action='store_true', help='启用URL扫描（默认关闭）')
    parser.add_argument('--scan-api', action='store_true', help='启用API端点扫描（默认关闭）')
    parser.add_argument('--scan-secrets', action='store_true', help='启用敏感信息扫描（默认关闭）')
    parser.add_argument('--scan-all', action='store_true', help='启用所有扫描功能')

    # 扫描模式选项
    parser.add_argument('--quick', action='store_true', help='快速扫描模式（只扫描主页JS文件）')
    parser.add_argument('--deep', action='store_true', help='深度扫描模式（更深层递归）')
    parser.add_argument('--depth', type=int, default=1, help='设置最大递归深度（默认：1）')
    parser.add_argument('--quick-timeout', type=int, default=10, help='快速模式超时时间（秒，默认：10）')
    parser.add_argument('--count-only', action='store_true', help='仅显示JS文件数量，不显示详细列表')
    
    args = parser.parse_args()
    
    if not args.url and not args.file:
        parser.print_help()
        return
    
    scan_urls = args.scan_urls or args.scan_all
    scan_api = args.scan_api or args.scan_all
    scan_secrets = args.scan_secrets or args.scan_all

    # 确定扫描模式
    scan_mode = ScanMode.STANDARD
    if args.quick:
        scan_mode = ScanMode.QUICK
    elif args.deep:
        scan_mode = ScanMode.DEEP

    config = Config(
        threads=args.threads,
        cookie=args.cookie,
        proxy=args.proxy,
        enable_url_scan=scan_urls,
        enable_api_scan=scan_api,
        enable_secret_scan=scan_secrets,
        scan_mode=scan_mode,
        quick_timeout=args.quick_timeout,
        max_depth=args.depth
    )
    
    result_manager = ResultManager()
    
    crawler = Crawler(config, result_manager)
    
    try:
        if args.url:
            url = args.url
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            if not validate_url(url):
                print(f"Error: Invalid URL - {url}")
                return
            
            print(f"Starting crawl: {url}")
            config.target_url = url
            crawler.crawl_single(url)
        
        elif args.file:
            print(f"Starting batch crawl: {args.file}")
            crawler.crawl_batch(args.file)
        
        if args.count_only:
            result_manager.print_count_only(config)
        else:
            result_manager.print_results(config)
        
        if args.output:
            result_manager.export_results(args.output, config)
        
        auto_report_path = result_manager.generate_auto_report(config)
        if auto_report_path:
            print(f"\n\033[92mJSHunter HTML报告已自动生成: {auto_report_path}\033[0m")
            
    except KeyboardInterrupt:
        print("\nUser interrupted")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()