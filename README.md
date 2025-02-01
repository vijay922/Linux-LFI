# Linux Path Traversal Vulnerability Scanner

## Overview
This Go script is designed to detect **path traversal vulnerabilities** in web applications by testing various URL payloads that attempt to access the `/etc/passwd` file on a target server.

## Features
- Reads a list of target URLs from a file.
- Generates different path traversal payloads.
- Tests path traversal attacks in both **URL paths** and **query parameters**.
- Identifies vulnerable URLs based on the presence of `root:x:0:0:` in the response.
- Supports verbose output (`-v`) to display scan details.
- Saves results to a file if specified (`-o`).
- Uses a custom **User-Agent** to mimic a real browser.

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
go . build -o lfi-scanner
```

### Run the Scanner
```sh
./lfi-scanner -l urls.txt -v -o results.txt
```

### Command-Line Arguments
| Flag  | Description |
|-------|-------------|
| `-l`  | Path to the file containing URLs (required) |
| `-v`  | Enable verbose output (optional) |
| `-o`  | Save results to a specified file (optional) |

## How It Works
1. **Reads URLs** from the provided file.
2. **Generates test URLs** by injecting different path traversal payloads.
3. **Sends HTTP GET requests** using a custom User-Agent.
4. **Analyzes responses** to check if they contain the `/etc/passwd` file contents.
5. **Logs and saves results** of vulnerable URLs.

## Example URL Payloads Tested
- `../../../../etc/passwd`
- `....//....//....//etc/passwd`
- `/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`
- `..%252f..%252f..%252fetc/passwd`
- `/etc/passwd`

## Output Example
```
[VULNERABLE] http://example.com/download?file=../../../../etc/passwd
[SAFE] http://example.com/view?id=123
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

