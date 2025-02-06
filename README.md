# Path Traversal Vulnerability Scanner

## Overview
This Go-based scanner is designed to identify **Path Traversal** vulnerabilities in web applications. It systematically tests URLs with various payloads that attempt to access sensitive system files (e.g., `/etc/passwd` on Linux or `win.ini` on Windows). The scanner performs automated checks, detects vulnerable endpoints, and logs the results.


## Features
- Reads a list of target URLs from a file.
- Supports multiple **payloads** for path traversal exploitation.
- Concurrent scanning with configurable worker threads.
- Supports **verbose mode** for detailed request-response logging.
- Saves vulnerable results to an output file.
- Handles **gzip-compressed** responses.
- Bypasses common path traversal filtering techniques.
- Skips SSL certificate verification for HTTPS targets.

## Installation & Usage
### Prerequisites
Ensure you have **Go installed** on your system.

### Clone the Repository
```sh
git clone https://github.com/vijay922/Linux-LFI.git
cd Linux-LFI
```

### Build the Scanner
```sh
go build linux-lfi.go
mv linux-lfi /usr/local/bin
```

### Run the Scanner
```sh
$ linux-lfi -l urls.txt -v -o results.txt
```

### Command-Line Arguments
| Flag  | Description |
|-------|-------------|
| `-l`  | Path to the file containing URLs (required) |
| `-v`  | Enable verbose output (optional) |
| `-o`  | Save results to a specified file (optional) |

## How It Works
1. **Reads URLs** from the provided file.
2. **Generates test URLs** by injecting path traversal payloads.
3. **Performs HTTP requests** with crafted payloads.
4. **Parses responses** and checks for system file leakage (e.g., `/etc/passwd`, `win.ini`).
5. **Logs vulnerable URLs** if sensitive content is detected.
6. **Saves results** to an output file (if specified).

## Example URL Payloads Tested
- `../../../../etc/passwd`
- `....//....//....//etc/passwd`
- `/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`
- `..%252f..%252f..%252fetc/passwd`
- `/etc/passwd`

## Output Example
```
Vulnerable URL: http://example.com/download?file=../../../../etc/passwd
Request:
GET /download?file=../../../../etc/passwd HTTP/1.1
Host: example.com
...

Response:
HTTP/1.1 200 OK
...
root:x:0:0:root:/root:/bin/bash
```

## Disclaimer
This tool is for **educational and ethical security testing** only. Do not use it on systems you do not have explicit permission to test.

## License
[MIT License](LICENSE)

<h2 id="donate" align="center">⚡️ Support</h2>

<details>
<summary>☕ Buy Me A Coffee</summary>

<p align="center">
  <a href="https://buymeacoffee.com/vijay922">
    <img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black"/>
  </a>
</p>

</details>

<p align="center">
  <b><i>"Keep pushing forward. Never surrender."</i></b>
</p>

<p align="center">🌱</p>



## Author
[chippa vijay kumar](https://github.com/vijay922)

