# 🛠️ CTF Automation Toolkit

**A modular Python CLI toolkit for CTF competitions, OSINT, and forensic analysis.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-160%20passing-brightgreen?style=flat-square&logo=pytest&logoColor=white)](tests/)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active%20Development-f59e0b?style=flat-square)]()
[![Stage](https://img.shields.io/badge/Stage-MVP%20Complete-6366f1?style=flat-square)]()

</div>

---

## What is this?

CTF Toolkit is a command-line suite that automates the repetitive grunt-work in Capture The Flag competitions — identifying mystery hashes, decoding layered encodings, ripping metadata from challenge files, cracking nested zip archives, and running OSINT lookups — all from one consistent interface with clean, readable output.

It's designed to be **modular** (each capability is a self-contained module), **extensible** (Stage 2 and 3 modules are in progress), and **readable** (every command produces structured Rich output, not walls of raw text).

> **For CTFs, educational labs, and authorised security testing only.**
> Do not use against systems you do not own or have explicit written permission to test.

---

## Modules

| Module | Status | Commands | Description |
|---|---|---|---|
| `hash` | ✅ MVP | `identify` `crack` | Identify hash types, dictionary crack with progress |
| `encode` | ✅ MVP | `base64` `base32` `base58` `hex` `rot13` `url` `binary` `morse` `html` `detect` | Encode/decode in 9 formats + auto-detect |
| `metadata` | ✅ MVP | `analyze` `dump` | EXIF from images, properties from PDFs and Office docs |
| `zip` | ✅ MVP | `extract` `inspect` | Recursive extraction, password cracking, zip bomb detection |
| `osint` | ✅ MVP | `whois` `dns` `resolve` `subdomains` | WHOIS, full DNS records, reverse lookup, subdomain brute-force |
| `web` | 🔄 Stage 2 | `headers` `robots` `cookies` `fuzz` | HTTP header analysis, robots.txt, JWT decoder, directory fuzzing |
| `stego` | 🔄 Stage 2 | `lsb` `strings` `exif` `signature` | LSB detection, strings extraction, file signature analysis |
| `pcap` | 🔄 Stage 2 | `analyze` `http` `creds` | Protocol summary, HTTP object extraction, credential patterns |
| `ai` | 🔄 Stage 3 | `analyze` `suggest` | AI-assisted challenge analysis (Ollama / OpenAI) |

---

## Installation

**Requirements:** Python 3.11+

```bash
# 1. Clone
git clone https://github.com/yourusername/ctf-toolkit.git
cd ctf-toolkit

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify
python main.py --help
```

> **Tip:** Add an alias to your shell config for faster access during a CTF:
> ```bash
> alias ctf="python /path/to/ctf-toolkit/main.py"
> ```

---

## Usage

### Hash Module

Identify a mystery hash by length and format, then optionally crack it with a wordlist.

```bash
# Identify — returns algorithm candidates with confidence, hashcat mode, and john format
python main.py hash identify 5d41402abc4b2a76b9719d911017c592

# Crack — dictionary attack, auto-detects algorithm from hash length
python main.py hash crack 5d41402abc4b2a76b9719d911017c592

# Crack with a custom wordlist and force a specific algorithm
python main.py hash crack <hash> --wordlist /usr/share/wordlists/rockyou.txt --algo sha256
```

**Supported algorithms:** MD5, NTLM, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, bcrypt, sha512crypt, sha256crypt, md5crypt, MySQL 3.x / 4.1+, CRC-32

---

### Encoding Module

Encode and decode data in any of 9 formats. Every command takes `--decode` to reverse direction.
The `detect` command tries all decoders at once — useful when you have no idea what something is.

```bash
# Encode
python main.py encode base64 "hello world"           # → aGVsbG8gd29ybGQ=
python main.py encode hex "hello"                    # → 68656c6c6f
python main.py encode binary "hi"                    # → 01101000 01101001
python main.py encode morse "SOS"                    # → ... --- ...
python main.py encode rot13 "secret"                 # + prints all 25 rotations

# Decode (add --decode / -d to any command)
python main.py encode base64 "aGVsbG8gd29ybGQ=" --decode
python main.py encode hex "68656c6c6f" --decode
python main.py encode binary "01101000 01101001" --decode

# Auto-detect — tries all decoders and shows every successful result
python main.py encode detect "aGVsbG8="
python main.py encode detect "68656c6c6f"
python main.py encode detect "... --- ..."
```

**Supported formats:** Base64, Base32, Base58, Hex, ROT-N (any rotation), URL, Binary, Morse, HTML entities

---

### Metadata Module

Extract metadata from images, PDFs, and Office documents. File type is detected automatically from magic bytes — no need to specify the format.

```bash
# Analyze — structured output grouped by category (device, timestamps, GPS, etc.)
python main.py metadata analyze photo.jpg
python main.py metadata analyze report.pdf
python main.py metadata analyze challenge.docx

# Verbose — adds full raw tag dump at the end
python main.py metadata analyze suspicious.jpg --verbose

# Dump — every single raw EXIF/PDF/Office tag, useful for hunting hidden flags
python main.py metadata dump challenge.jpg
```

**What it extracts:**
- **Images:** Camera make/model, software, timestamps, GPS coordinates (with Google Maps link), orientation, exposure settings, artist, copyright, all raw EXIF tags
- **PDFs:** Title, author, creator, producer, creation/modification dates, encryption status, page count
- **Office (docx/xlsx/pptx):** Author, last modified by, company, application, revision count, word/page counts

---

### ZIP / Archive Module

Recursively extracts nested archives, cracks password-protected ZIPs against a wordlist, and runs safety checks before touching anything.

```bash
# Basic extraction — recursively dives into nested archives automatically
python main.py zip extract challenge.zip

# Custom output directory
python main.py zip extract challenge.zip --output ~/ctf/extracted

# Password-protected ZIP — tries wordlist automatically
python main.py zip extract locked.zip --wordlist wordlists/common.txt

# Inspect without extracting — shows file listing, sizes, encryption, safety report
python main.py zip inspect suspicious.zip
```

**Safety checks (run before every extraction):**
- Total uncompressed size limit (500 MB)
- Per-file size limit
- File count limit (10,000 files)
- Compression ratio check (flags ratios > 100:1 as potential zip bombs)
- Path traversal protection on TAR archives (`../` attempts are skipped)

**After extraction:** all final non-archive files are automatically surfaced to `<output>/found/` so you never have to dig through 10 nested folders to find `flag.txt`.

**Supported formats:** `.zip`, `.tar`, `.tar.gz`, `.tgz`, `.tar.bz2`

---

### OSINT Module

```bash
# WHOIS — registrar, dates, name servers, registrant info
python main.py osint whois example.com
python main.py osint whois example.com --verbose      # + raw WHOIS text

# DNS — query specific record types, or all at once
python main.py osint dns example.com                  # all record types
python main.py osint dns example.com --type MX
python main.py osint dns example.com --type TXT
python main.py osint dns example.com --nameserver 1.1.1.1

# Resolve — domain → IPs (A + AAAA), or IP → hostname (auto-detects)
python main.py osint resolve example.com
python main.py osint resolve 93.184.216.34            # reverse PTR lookup

# Subdomain enumeration — concurrent DNS brute-force
python main.py osint subdomains example.com
python main.py osint subdomains example.com --wordlist subdomains.txt
python main.py osint subdomains example.com --threads 50 --nameserver 8.8.8.8
```

**DNS record types:** A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA

**Subdomain enumerator:** 30 concurrent threads by default, 100+ built-in common subdomains, detects both A records and CNAMEs.

---

## Common CTF Workflows

**Unknown hash in a challenge file:**
```bash
python main.py hash identify <hash>            # → "SHA-256, high confidence"
python main.py hash crack <hash> -w rockyou.txt
```

**Layered encoding (base64 of hex of rot13 of ...):**
```bash
python main.py encode detect "<mystery string>"   # tries everything at once
# decode layer by layer from there
```

**Suspicious image with hidden data:**
```bash
python main.py metadata analyze image.jpg --verbose    # full EXIF dump
python main.py metadata dump image.jpg                 # every raw tag
```

**Matryoshka ZIP challenge:**
```bash
python main.py zip inspect nested.zip             # pre-flight check
python main.py zip extract nested.zip             # auto-recurses all layers
# → flag surfaced to nested_out/found/flag.txt
```

**Target domain recon:**
```bash
python main.py osint whois target.com
python main.py osint dns target.com               # all records
python main.py osint subdomains target.com        # find exposed services
```

---

## Project Structure

```
ctf-toolkit/
├── main.py                      # Typer app, subcommand registration, banner
├── requirements.txt
│
├── modules/
│   ├── hashes/
│   │   ├── __init__.py          # CLI: hash identify, hash crack
│   │   ├── identifier.py        # Pattern matching against 15+ hash types
│   │   └── cracker.py           # Dictionary attack with Rich progress bar
│   │
│   ├── encodings/
│   │   ├── __init__.py          # CLI: encode/decode commands + detect
│   │   └── codecs.py            # Pure encode/decode functions for all 9 formats
│   │
│   ├── metadata/
│   │   ├── __init__.py          # CLI: metadata analyze, metadata dump
│   │   ├── detector.py          # Magic byte + extension type detection
│   │   ├── image_extractor.py   # EXIF via exifread + PNG tEXt chunks
│   │   ├── pdf_extractor.py     # PDF info dict via PyPDF2
│   │   └── office_extractor.py  # OOXML core.xml + app.xml parser
│   │
│   ├── ziptools/
│   │   ├── __init__.py          # CLI: zip extract, zip inspect + surface helper
│   │   ├── extractor.py         # Recursive extraction engine (ZIP + TAR)
│   │   └── safety.py            # Pre-flight safety checks, zip bomb detection
│   │
│   ├── osint/
│   │   ├── __init__.py          # CLI: whois, dns, resolve, subdomains
│   │   ├── whois_lookup.py      # WHOIS with normalised output
│   │   ├── dns_lookup.py        # All DNS record types via dnspython
│   │   └── subdomain.py         # Concurrent brute-force enumerator
│   │
│   ├── web/                     # [Stage 2]
│   ├── stego/                   # [Stage 2]
│   ├── pcap/                    # [Stage 2]
│   └── ai/                      # [Stage 3]
│
├── utils/
│   ├── logger.py                # info/success/warning/error/section helpers
│   ├── helpers.py               # resolve_file, read_wordlist, shared utils
│   └── output.py                # kv_table, result_panel, multi_table
│
├── wordlists/
│   └── common.txt               # Default password + subdomain wordlist
├── reports/                     # Reserved for future report export
├── plugins/                     # Reserved for Stage 3 plugin system
└── tests/
    ├── test_hashes.py            # 21 tests
    ├── test_encodings.py         # 54 tests
    ├── test_metadata.py          # 24 tests
    ├── test_ziptools.py          # 28 tests
    └── test_osint.py             # 33 tests
```

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run a specific module's tests
pytest tests/test_hashes.py -v
pytest tests/test_encodings.py -v

# With coverage report
pytest tests/ --cov=modules --cov-report=term-missing

# Current status
# 160 tests — 0 failures
```

---

## Dependencies

| Library | Purpose |
|---|---|
| `typer` | CLI framework, subcommand structure |
| `rich` | Coloured output, tables, progress bars |
| `exifread` | Image EXIF metadata extraction |
| `PyPDF2` | PDF metadata extraction |
| `dnspython` | DNS queries (all record types) |
| `python-whois` | WHOIS lookups |
| `requests` | HTTP requests (Stage 2) |
| `beautifulsoup4` | HTML parsing (Stage 2) |
| `scapy` | Packet analysis (Stage 2) |
| `pytest` | Test suite |

---

## Roadmap

**MVP — Complete ✅**
- [x] CLI framework, banner, module registration
- [x] Hash identification (15+ types) and dictionary cracking
- [x] Encoding/decoding (9 formats + auto-detect)
- [x] Metadata extraction (images, PDFs, Office docs)
- [x] Recursive archive extractor with zip bomb protection and flag surfacing
- [x] OSINT suite (WHOIS, DNS, reverse lookup, subdomain enumeration)

**Stage 2 — In Progress 🔄**
- [ ] Web challenge tools (HTTP headers, robots.txt, cookie/JWT decoder, directory fuzzing)
- [ ] Steganography helpers (LSB detection, strings extraction, file signature analysis)
- [ ] PCAP analysis (protocol summary, HTTP object extraction, credential detection)

**Stage 3 — Planned 📋**
- [ ] AI assistant module (Ollama / OpenAI) — challenge category detection, tool suggestions
- [ ] Automatic file type + encoding detection pipeline
- [ ] Plugin system (`ctf-toolkit plugin install <module>`)
- [ ] HTML / JSON report export (`--report`)
- [ ] `--output` flag standardised across all modules
- [ ] Changelog and versioning

---

## Contributing

Contributions are welcome. Please open an issue before submitting a large PR so we can discuss the approach first.

For new modules, follow the existing pattern:
- Logic goes in a dedicated file (e.g. `modules/newmod/engine.py`)
- CLI commands go in `modules/newmod/__init__.py` as a Typer app
- Register the app in `main.py`
- Add tests in `tests/test_newmod.py`

---

## License

MIT — see [LICENSE](LICENSE) for details.
