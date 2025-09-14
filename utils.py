from urllib.parse import urlparse

def print_banner():
    print("""\033[96m
      _  _____ _    _ _    _ _   _ _______ ______ _____  
     | |/ ____| |  | | |  | | \\ | |__   __|  ____|  __ \\ 
     | | (___ | |__| | |  | |  \\| |  | |  | |__  | |__) |
 _   | |\\___ \\|  __  | |  | | . ` |  | |  |  __| |  _  / 
| |__| |____) | |  | | |__| | |\\  |  | |  | |____| | \\ \\ 
 \\____/|_____/|_|  |_|\\____/|_| \\_|  |_|  |______|_|  \\_\\

JSHunter - Advanced JavaScript Discovery Tool
Optimized for Penetration Testing & Security Assessment
\033[0m""")

def validate_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def get_file_extension(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path
    
    if '.' in path:
        return path.split('.')[-1].lower()
    
    return ''

def is_javascript_file(url: str) -> bool:
    return get_file_extension(url) == 'js'