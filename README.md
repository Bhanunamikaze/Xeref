# Xeref - Automated Reconnaissance Tool

**One solution for all bug bounty passive & active unauthenticated reconnaissance.**

Xeref is a Python script designed to automate the initial reconnaissance phase for bug bounty hunting and penetration testing. It orchestrates a variety of popular open-source tools to gather comprehensive information about one or more target domains.

## Features

* **Multi-Target Input:** Scan single domains or provide a list of domains in a file.
* **Parallel Processing:** Leverages multithreading to run scans concurrently for speed and efficiency.
* **Comprehensive Subdomain Enumeration:** Integrates numerous tools for finding subdomains:
    * Amass, Subfinder, Sublist3r, OneForAll, Assetnote, Knockpy, Sudomy, bbot, Censys, Assetfinder, crtsh.py, SecurityTrails.
* **Port Scanning:** Uses `masscan` for fast initial port discovery and `nmap` with `-sCV` for detailed service/version identification on discovered open ports.
* **Web Server Discovery:** Identifies live web servers using `httprobe`.
* **Web Application Analysis:**
    * **Vulnerability Scanning:** Runs `nuclei` (general templates) and `nikto`.
    * **Takeover Checks:** Uses `subjack` and specific `nuclei` takeover templates.
    * **Visual Recon:** Takes screenshots with `eyewitness`.
    * **URL & Endpoint Discovery:** Uses `waybackurls`, `gospider`, `gau`, and `js-scanner`.
    * **Technology Fingerprinting:** Identifies technologies with `wappalyzer` (Docker) and `webanalyze`.
    * **Directory Discovery:** Finds directories/files using `dirsearch`.
    * **CORS Checks:** Uses `corsy`.
* **CMS Scanning:** Performs WordPress-specific scans using `wpscan`.
* **S3 Bucket Checks:** Identifies potential S3 buckets derived from subdomains and checks their accessibility using `s3scanner` and `AWSBucketDump`.
* **Secrets Scanning (Optional):** Scans a local directory (e.g., a cloned code repository) for leaked secrets using `git-secrets`, `gitleaks`, and `trufflehog`.
* **Tool Installation Helper:** Checks for missing tools and can attempt automated installation (primarily for Debian/Ubuntu based systems).
* **Granular Control:** Allows skipping specific phases or running only selected phases using command-line flags.
* **HTML Reporting:** Generates a consolidated HTML report with summaries and links to detailed output files, updated incrementally during the scan.

## Tools Used

Xeref orchestrates the following external tools. **These must be installed** for the script to function fully.

* **Subdomain Enum:** Amass, Subfinder, Sublist3r, OneForAll, Knockpy, Sudomy, bbot, Assetfinder, crtsh.py
* **APIs/Web:** SecurityTrails (API Key), Assetnote (API Key), Censys (API Key), curl, jq
* **Port Scanning:** Masscan, Nmap
* **Web Discovery:** httprobe, Waybackurls, GAU, GoSpider, Dirsearch, JSScanner
* **Vulnerability/Info:** Nuclei, Nikto, WPScan, Subjack, Corsy
* **Technology:** Wappalyzer (via Docker), Webanalyze, Docker
* **Screenshots:** Eyewitness
* **Secrets:** Git, Git-Secrets, Gitleaks, TruffleHog
* **Utilities:** Python3, pip3, Go, Ruby, Gem, Bundle, dnsx

## Installation

1.  **Prerequisites:**
    * Python 3.x and pip3
    * Go environment properly set up (`GOPATH`, `GOBIN` in `PATH`)
    * Ruby and Gem
    * Docker installed and running
    * Git
    * Standard build tools (`build-essential` on Debian/Ubuntu)
    * Ensure you have necessary permissions (potentially `sudo`) for installations.

2.  **Clone the Repository:**
    ```bash
    git clone [https://github.com/Bhanunamikaze/Xeref.git](https://github.com/Bhanunamikaze/Xeref.git)
    cd Xeref
    ```

3.  **Install Tools:**
    * **Automated Attempt (Recommended):** The script can attempt to install most dependencies. Run:
        ```bash
        sudo python3 xeref.py --install-tools
        ```
        * This will check for missing tools and try to install them using `apt`, `go install`, `pip3`, and `git clone`.
        * **Note:** Commands requiring `sudo` are included. The script itself doesn't handle the `sudo` password prompt within the installation commands; you might need to run the *entire script* with `sudo` for these parts, or run the failed commands manually afterwards.
        * Pay attention to any "Manual Installation Notes" printed at the end for tools like Sniper or crtsh.py that require manual steps.
        * Ensure the `INSTALL_DIR` variable in the script (`/home/kali/Desktop/Bounty/Tools` by default) is writable by the user running the installation, or change it to a suitable path (e.g., `~/.local/share/xeref_tools`).
    * **Manual Installation:** Alternatively, install each tool listed in the "Tools Used" section manually according to their official documentation.

4.  **API Keys (Optional but Recommended):**
    * Set environment variables for better results with certain tools:
        ```bash
        export SECURITYTRAILS_API_KEY="YOUR_KEY_HERE"
        export ASSETNOTE_API_KEY="YOUR_KEY_HERE"
        # Configure Censys API ID/Secret if using censys-cli
        # Configure WPScan API token for full results (add --api-token to command if needed)
        ```

## Usage

```bash
# Make the script executable
chmod +x xeref.py

# Basic Scan (Single Target)
./xeref.py example.com

# Scan Multiple Targets
./xeref.py example.com anotherexample.org

# Scan Targets from a File
./xeref.py -f targets.txt

# Scan with Secrets Scanning on a Local Repo
./xeref.py example.com -s /path/to/local/repo

# Skip Specific Phases (e.g., skip port scanning and S3 checks)
./xeref.py example.com --skip-port-scan --skip-s3-check

# Run Only Specific Phases (e.g., only subdomain enum and httprobe)
./xeref.py example.com --only-run subdomain_enum,httprobe

# Increase Worker Threads
./xeref.py example.com -w 20

# Check/Install Tools Only
./xeref.py --install-tools

# Get Help
./xeref.py -h
```

## Output

* Results are saved in a timestamped directory (e.g., `xeref_results_YYYY-MM-DD_HHMMSS`).
* Each target domain gets its own sub-directory (`<target>/recon/`).
* A `_combined_results` directory stores aggregated data (consolidated subdomains, IPs, port scan results, etc.).
* An incrementally updated HTML report (`xeref_report.html`) is generated in the main results directory, providing a summary and links to all tool outputs.

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Running scans against systems without prior permission is illegal and unethical. The developers assume no liability and are not responsible for any misuse or damage caused by this script. Use responsibly.
