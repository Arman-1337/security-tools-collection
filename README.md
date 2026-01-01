# security-tools-collection
Collection of Python security automation tools for penetration testing and security analysis
# 🔐 Security Tools Collection

<div align="center">

![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)
![Security](https://img.shields.io/badge/security-tools-red.svg)

**A comprehensive collection of Python security automation tools for penetration testing, security analysis, and ethical hacking.**

[Features](#-features) • [Tools](#-tools) • [Installation](#-installation) • [Usage](#-usage) • [Contributing](#-contributing) • [License](#-license)

</div>

---

## 🎯 Overview

This repository contains a suite of professional-grade security tools developed for cybersecurity professionals, penetration testers, and security researchers. Each tool is designed to be modular, easy to use, and thoroughly documented.

**⚠️ IMPORTANT:** These tools are for **educational and authorized security testing purposes ONLY**. Always obtain proper authorization before testing any systems.

---

## ✨ Features

- 🐍 **Pure Python** - No complex dependencies, easy to run
- 🚀 **Fast & Efficient** - Optimized algorithms for performance
- 📖 **Well Documented** - Comprehensive README for each tool
- 🎨 **Clean Code** - Professional, maintainable, and readable
- 🛡️ **Security Focused** - Built with security best practices
- 🔧 **Modular Design** - Use tools independently or together
- 💻 **Cross-Platform** - Works on Windows, Linux, and macOS

---

## 🛠️ Tools

### 1. 🔍 [Port Scanner](./port-scanner/)

Multi-threaded network port scanner for rapid security assessment.

**Features:**
- Multi-threaded scanning (100+ threads)
- Service detection for common ports
- Customizable port ranges (1-65535)
- Real-time progress tracking
- Fast and reliable

**Use Cases:**
- Network reconnaissance
- Service discovery
- Security auditing
- Firewall testing
```bash
python port-scanner/port_scanner.py
```

---

### 2. 🔐 [Password Strength Checker](./password-strength-checker/)

Advanced password security analyzer with entropy calculation and recommendations.

**Features:**
- Character variety analysis
- Common password detection
- Pattern recognition (keyboard patterns, sequences)
- Entropy calculation
- Crack time estimation
- Security recommendations

**Use Cases:**
- Password policy validation
- Security awareness training
- User password assessment
- Password generator validation
```bash
python password-strength-checker/password_checker.py
```

---

### 3. 🌐 [Network Monitor](./network-monitor/)

Real-time network traffic monitoring and packet analysis tool.

**Features:**
- Live packet capture
- Protocol detection (TCP, UDP, ICMP)
- IP address tracking
- Port monitoring
- Traffic statistics
- Connection monitoring mode

**Use Cases:**
- Network security monitoring
- Traffic analysis
- Intrusion detection
- Bandwidth monitoring
```bash
python network-monitor/network_monitor.py
```

---

### 4. 🛡️ [Vulnerability Scanner](./vulnerability-scanner/)

Automated web application security scanner for common vulnerabilities.

**Features:**
- SQL Injection detection
- Cross-Site Scripting (XSS) testing
- Security headers validation
- SSL/TLS analysis
- Information disclosure detection
- Comprehensive vulnerability reports

**Use Cases:**
- Web application security testing
- Compliance auditing
- Security assessments
- Penetration testing
```bash
python vulnerability-scanner/vuln_scanner.py
```

---

### 5. 🔓 [Hash Cracker](./hash-cracker/)

Password hash cracker supporting multiple algorithms and attack methods.

**Features:**
- Multiple hash types (MD5, SHA-1, SHA-256, SHA-512)
- Dictionary attack
- Brute force attack
- Hash type auto-detection
- Performance metrics
- Example hash generator

**Use Cases:**
- Password recovery
- Security research
- Cryptography education
- CTF challenges
```bash
python hash-cracker/hash_cracker.py
```

---

## 📦 Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Quick Start

1. **Clone the repository:**
```bash
   git clone https://github.com/Arman-1337/security-tools-collection.git
   cd security-tools-collection
```

2. **Install dependencies:**
```bash
   pip install -r requirements.txt
```

3. **Run any tool:**
```bash
   # Port Scanner
   python port-scanner/port_scanner.py
   
   # Password Strength Checker
   python password-strength-checker/password_checker.py
   
   # Network Monitor (may require admin/root)
   python network-monitor/network_monitor.py
   
   # Vulnerability Scanner
   python vulnerability-scanner/vuln_scanner.py
   
   # Hash Cracker
   python hash-cracker/hash_cracker.py
```

---

## 🚀 Usage

Each tool has its own dedicated README with detailed usage instructions, examples, and best practices.

### General Workflow

1. **Choose the appropriate tool** for your security task
2. **Read the tool's README** for specific instructions
3. **Obtain proper authorization** before testing
4. **Run the tool** with appropriate parameters
5. **Analyze results** and generate reports
6. **Document findings** for remediation

### Example: Complete Security Assessment
```bash
# 1. Scan for open ports
python port-scanner/port_scanner.py

# 2. Monitor network traffic
sudo python network-monitor/network_monitor.py

# 3. Test web application security
python vulnerability-scanner/vuln_scanner.py

# 4. Analyze password policies
python password-strength-checker/password_checker.py

# 5. Crack hashes for penetration testing
python hash-cracker/hash_cracker.py
```

---

## 📚 Documentation

Each tool includes:

- ✅ **README.md** - Comprehensive documentation
- ✅ **Usage Examples** - Real-world scenarios
- ✅ **Code Comments** - Inline documentation
- ✅ **Best Practices** - Security recommendations
- ✅ **Troubleshooting** - Common issues and solutions

---

## 🎓 Educational Resources

### Learn More About:

- **Network Security**: Understanding ports, protocols, and traffic analysis
- **Web Security**: OWASP Top 10, injection attacks, XSS
- **Cryptography**: Hashing algorithms, password security, encryption
- **Penetration Testing**: Methodology, tools, and techniques
- **Ethical Hacking**: Legal considerations, responsible disclosure

### Recommended Platforms:

- [TryHackMe](https://tryhackme.com/) - Interactive cybersecurity training
- [HackTheBox](https://www.hackthebox.eu/) - Penetration testing labs
- [OWASP](https://owasp.org/) - Web application security
- [PortSwigger Academy](https://portswigger.net/web-security) - Free web security training

---

## ⚖️ Legal Disclaimer

**READ THIS CAREFULLY BEFORE USING ANY TOOLS**

### ✅ Authorized Use:

- Testing systems you own
- Authorized penetration testing engagements
- Educational purposes in controlled environments
- Security research with permission
- CTF competitions and practice platforms

### ❌ Unauthorized Use:

- Testing systems without explicit permission
- Accessing others' accounts or data
- Causing damage or disruption
- Any illegal activities

**WARNING:** Unauthorized use of these tools may be illegal and result in criminal prosecution, civil lawsuits, and imprisonment. Always obtain explicit written permission before testing any systems you do not own.

The author assumes **NO responsibility** for misuse of these tools.

---

## 🛡️ Responsible Disclosure

If you discover vulnerabilities using these tools:

1. **Do NOT** exploit or share the vulnerability publicly
2. **Report** to the organization's security team immediately
3. **Allow time** for the organization to patch
4. **Follow** responsible disclosure guidelines
5. **Document** your findings professionally

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Ways to Contribute:

- 🐛 **Report Bugs** - Open an issue with details
- 💡 **Suggest Features** - Share your ideas
- 📝 **Improve Documentation** - Fix typos, add examples
- 🔧 **Submit Code** - Create pull requests
- ⭐ **Star the Project** - Show your support

### Contribution Guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Summary:**
- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Private use
- ⚠️ No warranty
- ⚠️ No liability

---

## 👤 Author

**Arman Bin Tahir**

- 🔐 Cybersecurity Engineer
- 🐍 Python Developer
- ☁️ Cloud Security Enthusiast

**Connect with me:**
- 📧 Email: armantahir.1023@gmail.com
- 💼 LinkedIn: [linkedin.com/in/arman-tahir](https://www.linkedin.com/in/arman-tahir-1b79b52b7/)
- 🐙 GitHub: [github.com/Arman-1337](https://github.com/Arman-1337)

---

## 🌟 Acknowledgments

- Thanks to the cybersecurity community for inspiration
- OWASP for security testing guidelines
- Python community for excellent libraries
- All contributors and users of this project

---

## 📊 Project Stats

- **Total Tools:** 5
- **Lines of Code:** 2000+
- **Languages:** Python 3.6+
- **Dependencies:** Minimal (requests, psutil)
- **License:** MIT
- **Status:** Active Development

---

## 🔄 Roadmap

### Planned Features:

- [ ] GUI Interface for all tools
- [ ] Additional vulnerability scanning modules
- [ ] Report generation (PDF/HTML)
- [ ] Database for scan results
- [ ] API endpoints for automation
- [ ] Docker containerization
- [ ] More hash algorithms
- [ ] Advanced brute force techniques
- [ ] Integration with other security tools

---

## 🐛 Known Issues

Currently no known critical issues. See [Issues](https://github.com/Arman-1337/security-tools-collection/issues) for open bug reports.

---

## 📞 Support

Need help? Found a bug?

- 📖 Check the [Documentation](https://github.com/Arman-1337/security-tools-collection)
- 💬 Open an [Issue](https://github.com/Arman-1337/security-tools-collection/issues)
- 📧 Email: armantahir.1023@gmail.com

---

<div align="center">

**⭐ If you find this project useful, please give it a star! ⭐**

Made by [Arman Bin Tahir](https://github.com/Arman-1337)

**For educational and authorized security testing purposes only.**

</div>


