# 🛠️ CTF Automation Toolkit

> A modular Python-based CLI toolkit for CTF competitions, OSINT, and beginner forensic analysis.

![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-yellow?style=flat-square)

---

## ⚠️ Legal Disclaimer

This toolkit is intended **exclusively** for:
- CTF (Capture The Flag) competitions
- Authorized security testing
- Educational cybersecurity labs

**Do not use against systems you do not own or have explicit permission to test.**

---

## ✨ Features

| Module     | Commands                                      | Status |
|------------|-----------------------------------------------|--------|
| `hash`     | identify, crack                               | ✅ MVP  |
| `encode`   | base64, hex, rot13, url, binary               | ✅ MVP  |
| `metadata` | analyze (images, PDFs, Office docs)           | ✅ MVP  |
| `zip`      | extract (recursive, nested, password)         | ✅ MVP  |
| `osint`    | whois, dns, resolve, subdomains               | ✅ MVP  |
| `web`      | headers, robots, cookies, brute-force         | 🔄 Stage 2 |
| `stego`    | lsb, strings, signatures                     | 🔄 Stage 2 |
| `pcap`     | analyze, extract-http, find-creds             | 🔄 Stage 2 |
| `ai`       | analyze, suggest                              | 🔄 Stage 3 |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ctf-toolkit.git
cd ctf-toolkit

# Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the toolkit
python main.py --help
```

### Optional: Install globally as a command
```bash
pip install --editable .
ctf-toolkit --help
```

---

## 🚀 Usage

```bash
# Hash identification
python main.py hash identify 5d41402abc4b2a76b9719d911017c592

# Hash cracking (dictionary)
python main.py hash crack 5d41402abc4b2a76b9719d911017c592 --wordlist wordlists/common.txt

# Encoding
python main.py encode base64 "hello world"
python main.py encode hex "hello"
python main.py encode rot13 "secret"

# Decoding
python main.py encode base64 "aGVsbG8gd29ybGQ=" --decode
python main.py encode hex "68656c6c6f" --decode

# Metadata analysis
python main.py metadata analyze photo.jpg
python main.py metadata analyze document.pdf

# Archive extraction
python main.py zip extract challenge.zip
python main.py zip extract nested.zip --wordlist wordlists/common.txt

# OSINT
python main.py osint whois example.com
python main.py osint dns example.com
python main.py osint resolve example.com
python main.py osint subdomains example.com
```

---

## 🗂️ Project Structure

```
ctf-toolkit/
├── main.py                  # Entry point, Typer app registration
├── requirements.txt
├── README.md
│
├── modules/
│   ├── hashes/              # Hash identification & cracking
│   ├── encodings/           # Encode/decode utilities
│   ├── metadata/            # File metadata extraction
│   ├── ziptools/            # Archive handling
│   ├── osint/               # WHOIS, DNS, subdomain tools
│   ├── web/                 # [Stage 2] Web challenge tools
│   ├── stego/               # [Stage 2] Steganography helpers
│   ├── pcap/                # [Stage 2] PCAP analysis
│   └── ai/                  # [Stage 3] AI assistant module
│
├── utils/
│   ├── logger.py            # Rich-powered logging
│   ├── helpers.py           # Shared utilities
│   └── output.py            # Tables, panels, formatting
│
├── wordlists/
│   └── common.txt           # Default password wordlist
├── reports/                 # Auto-generated output reports
├── plugins/                 # [Stage 3] Dynamic plugin directory
└── tests/                   # pytest test suite
```

---

## 🗺️ Roadmap

- [x] Project scaffold & CLI framework
- [x] Hash module (identify + crack)
- [x] Encoding/decoding module
- [x] Metadata extraction module
- [x] ZIP/archive extractor
- [x] OSINT module (WHOIS, DNS)
- [ ] Web challenge utilities
- [ ] Steganography helpers
- [ ] PCAP analysis tools
- [ ] AI assistant module (Ollama / OpenAI)
- [ ] Plugin system
- [ ] HTML/JSON report export
- [ ] `--output` flag on all modules

---

## 🧪 Testing

```bash
pytest tests/ -v
pytest tests/ --cov=modules --cov-report=term-missing
```

---

## 🤝 Contributing

Contributions welcome! Please open an issue before submitting large PRs.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
