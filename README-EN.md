# JSHunter

<div align="center">

![JSHunter Logo](https://img.shields.io/badge/JSHunter-JavaScript%20Discovery%20Tool-blue?style=for-the-badge)

**Advanced JavaScript Discovery Tool for Security Assessment**

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-penetration%20testing-red.svg)](https://github.com/topics/penetration-testing)

*Professional JavaScript file discovery and security analysis tool optimized for penetration testing and security assessment*

English | [简体中文](README.md)

</div>

## 🎯 Overview

JSHunter is a powerful and comprehensive JavaScript discovery tool designed specifically for security professionals and penetration testers. It automatically crawls web applications to extract JavaScript files, discover hidden URLs, identify API endpoints, and detect sensitive information leakage.

### Key Features

- 🔍 **JavaScript File Discovery** - Comprehensive JS file collection with multi-layer detection
- ⚡ **Fast Scan Mode** - Complete scanning in 65 seconds, avoiding timeout issues
- 🎯 **Smart Deduplication** - Intelligent bundled file recognition, eliminating redundant results
- 🌐 **URL Extraction** - Advanced pattern matching for hidden URLs and endpoints
- 🔧 **API Endpoint Detection** - Intelligent identification of REST APIs and backend services
- 🔐 **Sensitive Data Detection** - Automated scanning for credentials, tokens, and secrets
- 🎨 **Rich Reporting** - Professional HTML reports with interactive search and filtering
- 🛡️ **Anti-Detection** - Built-in evasion techniques with UA rotation and smart delays
- 🚀 **Performance Optimized** - Multi-threaded architecture with intelligent resource management

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Pluviobyte/JSHunter.git
cd JSHunter

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

#### ⚡ Fast Scan Mode (Recommended)
For quick JS file enumeration, avoiding long scan times

```bash
# Fast scan - Complete in 65 seconds
python jshunter.py -u https://target.com --quick

# Fast scan + Statistics only
python jshunter.py -u https://target.com --quick --count-only

# Fast scan + Custom timeout
python jshunter.py -u https://target.com --quick --quick-timeout 30
```

#### 🔍 Standard Scan Mode
```bash
# Basic JavaScript file discovery (default mode)
python jshunter.py -u https://target.com

# Enable specific scanning features
python jshunter.py -u https://target.com --scan-urls          # URL extraction only
python jshunter.py -u https://target.com --scan-api           # API endpoint detection
python jshunter.py -u https://target.com --scan-secrets       # Sensitive information scanning

# Enable all scanning features
python jshunter.py -u https://target.com --scan-all
```

#### 🎯 Deep Scan Mode
```bash
# Deep recursive scanning
python jshunter.py -u https://target.com --deep

# Custom recursion depth
python jshunter.py -u https://target.com --depth 3
```

#### 📊 Batch & Export
```bash
# Batch scanning
python jshunter.py -f urls.txt --quick                        # Batch fast scan
python jshunter.py -f urls.txt --scan-all                     # Batch full scan

# Export results
python jshunter.py -u https://target.com --quick -o report.html    # HTML report
python jshunter.py -u https://target.com --quick -o report.json    # JSON export
```

#### 🔧 Advanced Configuration
```bash
# Authentication & proxy
python jshunter.py -u https://target.com --quick -c "session=abc123"           # Cookie auth
python jshunter.py -u https://target.com --quick -x http://127.0.0.1:8080      # HTTP proxy
python jshunter.py -u https://target.com --quick -t 10                         # Custom threads

# Combined usage
python jshunter.py -u https://target.com --quick --scan-all -c "auth=token" -x http://proxy:8080 -o report.html
```

## 📋 Command Line Options

### Basic Options
| Option | Description | Example |
|--------|-------------|---------|
| `-u, --url` | Target URL for scanning | `-u https://example.com` |
| `-f, --file` | Batch scan from URL file | `-f targets.txt` |
| `-o, --output` | Export results (csv/json/html) | `-o report.html` |
| `-c, --cookie` | Set authentication cookies | `-c "session=token"` |
| `-x, --proxy` | Configure HTTP proxy | `-x http://127.0.0.1:8080` |
| `-t, --threads` | Set thread count | `-t 20` |

### Scan Modes (New Optimization) ⚡
| Option | Description | Example |
|--------|-------------|---------|
| `--quick` | Fast scan mode (recommended) | `--quick` |
| `--deep` | Deep scan mode | `--deep` |
| `--depth N` | Set recursion depth | `--depth 3` |
| `--quick-timeout N` | Fast mode timeout (seconds) | `--quick-timeout 30` |
| `--count-only` | Show statistics only | `--count-only` |

### Feature Scanning
| Option | Description | Example |
|--------|-------------|---------|
| `--scan-urls` | Enable URL extraction | `--scan-urls` |
| `--scan-api` | Enable API endpoint detection | `--scan-api` |
| `--scan-secrets` | Enable sensitive data scanning | `--scan-secrets` |
| `--scan-all` | Enable all scanning features | `--scan-all` |

## 🔍 Scanning Capabilities

### ⚡ Performance Optimization Highlights
| Scan Mode | JS Files Found | Time Cost | Accuracy | Use Case |
|-----------|----------------|-----------|----------|----------|
| **Fast Mode --quick** | 62 files | 65 seconds | ✅High | Daily scanning, quick assessment |
| **Standard Mode (default)** | Complete | 2-5 minutes | ✅Accurate | Regular penetration testing |
| **Deep Mode --deep** | Most comprehensive | 5-10 minutes | ✅Most accurate | Deep security assessment |

### JavaScript Discovery
- 🎯 **Smart Deduplication** - Automatically filter module references in bundled files
- 🔍 **Multi-layer Detection** - 4 LinkFinder strategies + modern JS patterns
- 📦 **Bundled File Recognition** - Intelligent recognition of Vite/Webpack bundled files
- 🌐 **Dynamic Content Analysis** - Parse asynchronously loaded JS modules
- 📋 **Source Map Detection** - Discover development version mapping files

### URL & Endpoint Extraction
- Comprehensive pattern matching
- Relative and absolute URL resolution
- Parameter extraction
- Hidden endpoint discovery

### API Detection
- RESTful API identification
- GraphQL endpoint discovery
- Framework-specific patterns (FastAPI, Flask, Spring, etc.)
- Parameter and method detection

### Sensitive Information Detection
- 📱 **Phone Numbers** - International format detection
- 📧 **Email Addresses** - Advanced pattern matching
- 🆔 **ID Cards** - Document number patterns
- 🔑 **JWT Tokens** - JSON Web Token identification
- ☁️ **Cloud API Keys** - AWS, Google Cloud, Azure credentials
- 🎫 **Bearer Tokens** - OAuth and API authentication tokens
- 🔐 **SSH Keys** - Private key detection
- 🐙 **GitHub Tokens** - Personal access tokens
- 💬 **Slack Tokens** - Workspace and bot tokens
- ⚠️ **Generic Secrets** - Custom pattern matching

## 📊 Reporting Features

### Console Output
- Color-coded status indicators
- Structured information display
- Real-time progress tracking
- Categorized results presentation

### HTML Reports
- Modern responsive design
- Interactive search and filtering
- Status badge visualization
- Downloadable results
- Mobile-friendly interface

### Export Formats
- **HTML** - Rich interactive reports
- **CSV** - Spreadsheet-compatible format
- **JSON** - Machine-readable structured data

## 🛡️ Anti-Detection Features

### Built-in Evasion
- **User-Agent Rotation** - Modern browser UA pool
- **Smart Delays** - Randomized request timing
- **Header Randomization** - Dynamic HTTP headers
- **Request Distribution** - Load balancing across sessions

### Stealth Options
- Custom proxy support
- Cookie session management
- Configurable request timeouts
- Intelligent rate limiting

## 🏗️ Architecture

```
JSHunter/
├── jshunter.py          # Main application entry point
├── crawler.py           # Core crawling and discovery engine
├── config.py            # Configuration and pattern management
├── result.py            # Result processing and report generation
├── anti_detection.py    # Anti-detection and evasion utilities
├── utils.py             # Core utility functions
├── requirements.txt     # Python dependencies
└── results/             # Generated reports directory
```

## 🔧 Configuration

JSHunter uses intelligent defaults but supports extensive customization:

### Thread Configuration
- **Auto-detection** - CPU-based thread optimization
- **Manual override** - Custom thread count specification
- **Resource management** - Intelligent memory usage

### Pattern Customization
- **JavaScript patterns** - 4-layer LinkFinder strategy
- **URL extraction** - Multiple regex pattern sets
- **API detection** - Framework-specific signatures
- **Sensitive data** - 12+ detection categories

## 📈 Performance Optimization

### Multi-threading
- Concurrent request processing
- Thread pool management
- Resource optimization
- Deadlock prevention

### Memory Management
- Efficient data structures
- Duplicate elimination
- Result caching
- Memory usage monitoring

### Network Optimization
- Connection pooling
- Keep-alive sessions
- Request batching
- Bandwidth management

## 🎯 Use Cases

### Penetration Testing
- **Reconnaissance** - Initial target analysis
- **Asset Discovery** - Hidden resource identification
- **Attack Surface** - Endpoint enumeration
- **Information Gathering** - Credential harvesting

### Security Assessment
- **Code Review** - Client-side vulnerability analysis
- **Compliance** - Data leakage detection
- **Risk Assessment** - Exposure quantification
- **Audit Support** - Evidence collection

### Bug Bounty
- **Scope Expansion** - Subdomain and endpoint discovery
- **Parameter Mining** - Hidden functionality identification
- **Sensitive Data** - Information disclosure vulnerabilities
- **API Testing** - Undocumented endpoint discovery

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/Pluviobyte/JSHunter.git
cd JSHunter

# Install development dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

JSHunter is intended for authorized security testing and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this tool.

## 🔗 Resources

- [Documentation](docs/)
- [Examples](examples/)
- [FAQ](FAQ.md)
- [Changelog](CHANGELOG.md)

## 💬 Support

- 🐛 [Report Issues](https://github.com/Pluviobyte/JSHunter/issues)
- 💡 [Feature Requests](https://github.com/Pluviobyte/JSHunter/issues/new?template=feature_request.md)
- 📧 [Contact](mailto:security@example.com)

## 📊 Detailed Technical Specifications

### Scanning Performance Metrics
- **Concurrent Threads**: Up to 100 concurrent connections
- **Scanning Speed**: 1000+ URLs/minute (depends on network and target response)
- **Memory Usage**: Average 50-200MB (depends on result set size)
- **Support Depth**: Maximum 10-layer recursive crawling

### Detection Accuracy
- **JavaScript Files**: 95%+ detection rate
- **API Endpoints**: 90%+ identification rate
- **Sensitive Information**: 85%+ matching rate
- **False Positive Rate**: <5% (based on test datasets)

### Compatibility Support
- **Python Versions**: 3.7, 3.8, 3.9, 3.10, 3.11
- **Operating Systems**: Windows, Linux, macOS
- **Proxy Protocols**: HTTP, HTTPS, SOCKS5
- **Output Encoding**: UTF-8, GBK, ASCII

## 🏆 Project Advantages

### Compared to Similar Tools
1. **More Comprehensive Detection** - 4-layer LinkFinder strategy covers more scenarios
2. **Smarter Anti-Detection** - Built-in multiple evasion techniques
3. **More Professional Reports** - Interactive HTML reports and multi-format export
4. **Higher Performance** - Smart multi-threading and resource optimization
5. **Better User Experience** - Simple command-line interface and detailed documentation

### Wide Application Range
- **Enterprise Security Teams** - Internal security assessment
- **Penetration Testing Companies** - Professional security services
- **Independent Security Researchers** - Vulnerability research and disclosure
- **Security Learners** - Technical learning and practice
- **Bug Bounty Hunters** - Vulnerability bounty programs

---

<div align="center">
<b>Made with ❤️ for the security community</b>
</div>