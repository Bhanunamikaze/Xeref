#!/usr/bin/env python3
import os
import sys
import subprocess
import shutil
import datetime
import glob
import re
import time
import xml.etree.ElementTree as ET
import concurrent.futures
import threading
import json
import argparse
import ipaddress
import socket

# --- Configuration ---
DEFAULT_MAX_WORKERS = 10
LONG_TIMEOUT = 10800

# Tool Installation Directory (Update This )
INSTALL_DIR = "/home/kali/Desktop/Bounty/Tools"
os.makedirs(INSTALL_DIR, exist_ok=True)


# Tool Paths
TOOL_PATHS = {
    "oneforall": os.path.join(INSTALL_DIR, "OneForAll", "oneforall.py"),
    "knockpy": "knockpy",
    "sublist3r": "sublist3r",
    "sudomy": "sudomy",
    "js-scanner": os.path.join(INSTALL_DIR, "JSScanner", "scanner"),
    "gau": os.path.expanduser("~/go/bin/gau"),
    "corsy": os.path.join(INSTALL_DIR, "Corsy", "corsy.py"),
    "subjack_fingerprints": os.path.join(INSTALL_DIR, "subjack", "fingerprints.json"),
    "s3scanner": os.path.join(INSTALL_DIR, "S3Scanner", "s3scanner.py"),
    "awsbucketdump": os.path.join(INSTALL_DIR, "AWSBucketDump", "AWSBucketDump.py"),
    "sniper": os.path.join(INSTALL_DIR, "Sn1per", "sniper"),
    "bbot": "bbot",
    "crtsh": "crtsh",
    "masscan": "masscan", 
    "dnsx": "dnsx", 

    # Tools usually installed to PATH:
    "amass": "amass",
    "subfinder": "subfinder",
    "curl": "curl",
    "jq": "jq",
    "censys": "censys",
    "nmap": "nmap",
    "httprobe": "httprobe",
    "nuclei": "nuclei",
    "subjack": "subjack",
    "waybackurls": "waybackurls",
    "nikto": "nikto",
    "gospider": "gospider",
    "eyewitness": "eyewitness",
    "docker": "docker",
    "webanalyze": "webanalyze",
    "dirsearch": "dirsearch",
    "wpscan": "wpscan",
    "git": "git",
    "python3": "python3",
    "pip3": "pip3",
    "go": "go",
    "ruby": "ruby",
    "gem": "gem",
    "bundle": "bundle",
    "gitleaks": "gitleaks",
    "trufflehog": "trufflehog",
    "assetfinder": "assetfinder",
}


# --- Thread-safe Printing ---
print_lock = threading.Lock()

def safe_print(message, file=sys.stdout):
    """Prints messages in a thread-safe manner."""
    with print_lock:
        print(message, file=file)

class CommandRunner:
    """Helper class to run external commands."""
    def __init__(self):
        pass

    def run(self, cmd, cwd=None, silent=False, capture_output=True, timeout=None):
        """Runs a command, captures stdout, optionally silences stderr."""
        thread_id = threading.get_ident()
        if not silent:
            safe_print(f"[THR-{thread_id}] Running: {cmd}")
        try:
            result = subprocess.run(
                cmd, shell=True, stdout=subprocess.PIPE if capture_output else subprocess.PIPE,
                stderr=subprocess.DEVNULL if silent else subprocess.PIPE, text=True, cwd=cwd,
                check=False, encoding='utf-8', errors='ignore', timeout=timeout
            )
            if not silent and result.returncode != 0:
                 if "bbot" in cmd and "sudo" in cmd and result.returncode != 0:
                      safe_print(f"[THR-{thread_id}] [*] Note: bbot command requires sudo. If it failed, try running the script with sudo.", file=sys.stderr)
                 elif "wpscan" in cmd and "sudo" in cmd and result.returncode !=0:
                      safe_print(f"[THR-{thread_id}] [*] Note: wpscan command requires sudo for some operations. If it failed, try running the script with sudo.", file=sys.stderr)
                 # Suppress masscan IPv6 error warning if it's the only error
                 elif "masscan" in cmd and "FAIL: failed to detect IPv6 address" in (result.stderr or "") and len((result.stderr or "").splitlines()) < 3:
                     pass # Ignore common, non-fatal masscan IPv6 warning
                 else:
                     safe_print(f"[THR-{thread_id}] [!] Warning: Command '{cmd.split()[0]}' returned non-zero exit code {result.returncode}", file=sys.stderr)
                     if result.stderr: safe_print(f"    Stderr: {result.stderr.strip()}", file=sys.stderr)
            return result.stdout.splitlines() if capture_output else []
        except subprocess.TimeoutExpired:
             safe_print(f"[THR-{thread_id}] [!] Error: Command '{cmd.split()[0]}' timed out after {timeout} seconds.", file=sys.stderr)
             return []
        except FileNotFoundError:
            missing_cmd = cmd.split()[0]; safe_print(f"[THR-{thread_id}] [!] Error: Command '{missing_cmd}' not found.", file=sys.stderr)
            return []
        except Exception as e:
            safe_print(f"[THR-{thread_id}] [!] Error running command '{cmd}': {e}", file=sys.stderr)
            return []

    def run_file_output(self, cmd, filepath, cwd=None, silent=False, timeout=None):
        """Runs a command expected to output to a file, then reads the file."""
        self.run(cmd, cwd=cwd, silent=silent, capture_output=False, timeout=timeout)
        time.sleep(3) # Allow time for file writing
        try:
            actual_filepath = filepath
            is_bbot_dir = "bbot" in cmd and os.path.isdir(filepath)

            if is_bbot_dir:
                # Look for specific bbot output files within any subdirectory
                bbot_files = glob.glob(os.path.join(filepath, "**", "output.txt"), recursive=True) + \
                             glob.glob(os.path.join(filepath, "**", "subdomains.txt"), recursive=True)
                if bbot_files:
                    # Prioritize output.txt if both exist? Or just take first? Let's take first.
                    actual_filepath = bbot_files[0]
                    # safe_print(f"[*] Found bbot output file: {actual_filepath}") # Debugging
                else:
                    if not silent: safe_print(f"[THR-{threading.get_ident()}] [!] Warning: bbot output directory '{filepath}' found, but no 'output.txt' or 'subdomains.txt' inside subdirectories.", file=sys.stderr)
                    return []
            elif os.path.isdir(filepath): # Handle other tools that might output to a dir (e.g., oneforall)
                 possible_files = glob.glob(os.path.join(filepath, "*.csv")) + \
                                  glob.glob(os.path.join(filepath, "*.txt"))
                 if possible_files:
                     actual_filepath = possible_files[0] # Take first found file
                 else:
                     if not silent: safe_print(f"[THR-{threading.get_ident()}] [!] Warning: Output directory '{filepath}' found, but no standard result file inside.", file=sys.stderr)
                     return []


            if os.path.exists(actual_filepath) and os.path.getsize(actual_filepath) > 0:
                 with open(actual_filepath, 'r', encoding='utf-8', errors='ignore') as f:
                     return [line.strip() for line in f if line.strip()]
            else: return []
        except Exception as e:
            safe_print(f"[THR-{threading.get_ident()}] [!] Error reading output file '{filepath}' (or derived path '{actual_filepath}'): {e}", file=sys.stderr)
            return []

# --- Utility Functions ---
runner = CommandRunner()

def make_dir(path):
    """Creates a directory if it doesn't exist."""
    if not os.path.isdir(path):
        try: os.makedirs(path, exist_ok=True)
        except OSError as e: safe_print(f"[!] Error creating directory {path}: {e}", file=sys.stderr)

def read_file_lines(filepath):
    """Reads non-empty lines from a file."""
    lines = set()
    if not os.path.exists(filepath): return []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                stripped = line.strip();
                if stripped: lines.add(stripped)
        return list(lines)
    except Exception as e: safe_print(f"[!] Error reading file {filepath}: {e}", file=sys.stderr); return []

def write_lines_to_file(filepath, lines):
    """Writes a list of lines to a file, ensuring uniqueness."""
    unique_lines = sorted(list(set(filter(None, lines))))
    try:
        parent_dir = os.path.dirname(filepath)
        if parent_dir: make_dir(parent_dir)
        with open(filepath, 'w', encoding='utf-8') as f:
            for line in unique_lines: f.write(line + "\n")
    except Exception as e: safe_print(f"[!] Error writing to file {filepath}: {e}", file=sys.stderr)

def check_tool_exists(tool_name, path_or_cmd=None):
    """Checks if a tool exists either by path or in system PATH."""
    check_path = path_or_cmd if path_or_cmd else TOOL_PATHS.get(tool_name)
    if not check_path: check_path = tool_name
    if os.path.isfile(check_path):
        if check_path.endswith(".py") and not shutil.which("python3"): return False
        return os.path.exists(check_path)
    if tool_name == "bbot" and not shutil.which(check_path):
        local_bin_path = os.path.expanduser("~/.local/bin/bbot")
        if os.path.exists(local_bin_path):
            TOOL_PATHS["bbot"] = local_bin_path; return True
    return bool(shutil.which(check_path))

def get_local_ip():
    """Attempts to get the primary local non-loopback IPv4 address."""
    s = None
    try:
        # Connect to an external host (doesn't actually send data)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1) # Add a timeout
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        return ip
    except Exception as e:
        safe_print(f"[!] Could not determine local IP: {e}. Masscan might fail without --source-ip.", file=sys.stderr)
        # Fallback: Try getting hostname and resolving that
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if not ip.startswith("127."): return ip
        except Exception: pass # Ignore errors in fallback
        return None
    finally:
        if s:
            s.close()


# --- Tool Installation ---
TOOL_INSTALL_CMDS = {
    # Apt Packages
    "nmap": "sudo apt update && sudo apt install -y nmap",
    "jq": "sudo apt update && sudo apt install -y jq",
    "git": "sudo apt update && sudo apt install -y git",
    "python3": "sudo apt update && sudo apt install -y python3",
    "pip3": "sudo apt update && sudo apt install -y python3-pip",
    "docker": "sudo apt update && sudo apt install -y docker.io && sudo systemctl start docker && sudo systemctl enable docker",
    "curl": "sudo apt update && sudo apt install -y curl",
    "nikto": "sudo apt update && sudo apt install -y nikto",
    "ruby": "sudo apt update && sudo apt install -y ruby-full build-essential",
    "wpscan": "sudo apt update && sudo apt install -y wpscan;sudo gem install ostruct;sudo gem install yajl-ruby",
    "nuclei": "sudo apt update && sudo apt install -y nuclei",
    "gitleaks": "sudo apt update && sudo apt install -y gitleaks",
    "subjack": f"sudo apt update && sudo apt install -y subjack && mkdir -p {INSTALL_DIR}/subjack && wget https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -O {TOOL_PATHS['subjack_fingerprints']}",
    "gospider": "sudo apt update && sudo apt install -y gospider",
    "httprobe": "sudo apt update && sudo apt install -y httprobe",
    "subfinder": "sudo apt update && sudo apt install -y subfinder",
    "sublist3r": "sudo apt update && sudo apt install -y sublist3r",
    "amass": "sudo apt update && sudo apt install -y amass",
    "s3scanner": "sudo apt update && sudo apt install -y s3scanner",
    "dirsearch": "sudo apt update && sudo apt install -y dirsearch",
    "trufflehog": "sudo apt update && sudo apt install -y trufflehog",
    "eyewitness": "sudo apt update && sudo apt install -y eyewitness",
    "knockpy": "sudo apt update && sudo apt install -y knockpy",
    "masscan": "sudo apt update && sudo apt install -y masscan",

    # Go Installs
    "go": "echo 'Go installation not automated. Please install Go manually (https://golang.org/doc/install) and set up GOPATH.'",
    "assetfinder": f"go install -v github.com/tomnomnom/assetfinder@latest && sudo cp $(go env GOPATH)/bin/assetfinder /usr/local/bin/",
    "waybackurls": f"go install -v github.com/tomnomnom/waybackurls@latest && sudo cp $(go env GOPATH)/bin/waybackurls /usr/local/bin/",
    "webanalyze": f"go install -v github.com/rverton/webanalyze/cmd/webanalyze@latest && sudo cp $(go env GOPATH)/bin/webanalyze /usr/local/bin/",
    "gau_go": f"go install -v github.com/lc/gau/v2/cmd/gau@latest && sudo cp $(go env GOPATH)/bin/gau /usr/local/bin/",
    "dnsx": f"go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && sudo cp $(go env GOPATH)/bin/dnsx /usr/local/bin/", # Added dnsx install

    # Pip Installs
    "censys": "pip3 install --user censys --break-system-packages",
    "bbot": "pip3 install --user bbot --break-system-packages && echo '[*] Note: You might need to add ~/.local/bin to your PATH for bbot to work.'",

    # Git Clone + Setup
    "oneforall": f"git clone https://github.com/shmilylty/OneForAll.git {INSTALL_DIR}/OneForAll && cd {INSTALL_DIR}/OneForAll && python3 -m pip install --user -U pip setuptools wheel --break-system-packages && pip3 install --user -r requirements.txt --break-system-packages",
    "sudomy": f"git clone --recursive https://github.com/screetsec/Sudomy.git {INSTALL_DIR}/Sudomy && cd {INSTALL_DIR}/Sudomy && pip3 install --user -r requirements.txt --break-system-packages && chmod +x sudomy.py && echo '[*] Note: Add {INSTALL_DIR}/Sudomy to your PATH or create alias: alias sudomy=python3 {INSTALL_DIR}/Sudomy/sudomy.py'",
    "js-scanner": f"git clone https://github.com/0x240x23elu/JSScanner.git {INSTALL_DIR}/JSScanner && cd {INSTALL_DIR}/JSScanner && pip3 install --user -r requirements.txt --break-system-packages && chmod +x scanner",
    "corsy": f"git clone https://github.com/s0md3v/Corsy.git {INSTALL_DIR}/Corsy",
    "awsbucketdump": f"git clone https://github.com/jordanpotti/AWSBucketDump.git {INSTALL_DIR}/AWSBucketDump && cd {INSTALL_DIR}/AWSBucketDump && pip3 install --user -r requirements.txt --break-system-packages",
    "sniper": f"git clone https://github.com/1N3/Sn1per {INSTALL_DIR}/Sn1per && echo '[!] Run sudo bash {INSTALL_DIR}/Sn1per/install.sh manually to complete Sniper setup.'",
    "crtsh": f"git clone https://github.com/YashGoti/crtsh.py.git {INSTALL_DIR}/crtsh.py && cd {INSTALL_DIR}/crtsh.py && mv crtsh.py crtsh && chmod +x crtsh && echo '[!] Run sudo cp {INSTALL_DIR}/crtsh.py/crtsh /usr/bin/ manually to add crtsh to PATH.'",

    # Manual / Placeholder
    "wpspider": "echo 'WPSpider installation not automated. Please install manually.'",
    "wprecon": "echo 'WPRecon installation not automated. Please install manually.'",
    "bundle": "echo 'Bundler should be installed via ruby gems (sudo gem install bundler).'",
    "gem": "echo 'RubyGems should be installed via ruby-full package.'",
}


ESSENTIAL_TOOLS = ["python3", "nmap", "httprobe", "nuclei", "git", "curl", "masscan", "dnsx"] # Added masscan, dnsx

def check_and_install_tools(force_install=False, skip_install=False):
    """Checks for required tools and optionally prompts/attempts installation."""
    if skip_install:
        safe_print("[*] Skipping tool installation check as requested.")
        all_essential_found = all(check_tool_exists(tool) for tool in ESSENTIAL_TOOLS)
        if not all_essential_found:
             missing_essentials = [t for t in ESSENTIAL_TOOLS if not check_tool_exists(t)]
             safe_print(f"[!] Essential tools missing: {', '.join(missing_essentials)}. Cannot proceed.", file=sys.stderr); sys.exit(1)
        return True

    safe_print("[*] Checking for required tools...")
    missing_tools = []; manual_install_notes = []
    all_defined_tools = set(TOOL_INSTALL_CMDS.keys()) | set(TOOL_PATHS.keys())
    checked_tools = set()

    # Check essential first
    for tool in ESSENTIAL_TOOLS:
        if not check_tool_exists(tool): missing_tools.append(tool)
        checked_tools.add(tool)
    # Check remaining defined tools
    for tool in sorted(list(all_defined_tools)):
        # Skip checks for placeholders or already checked tools
        if tool in ["subjack_fingerprints", "go", "gem", "bundle", "wpspider", "wprecon"] or tool in checked_tools: continue
        if not check_tool_exists(tool): missing_tools.append(tool)
        checked_tools.add(tool)

    if not missing_tools: safe_print("[+] All required tools seem to be installed."); return True

    safe_print("\n[!] The following tools appear to be missing or not executable:")
    for tool in missing_tools: safe_print(f"  - {tool}")

    install_confirmed = force_install
    if not force_install:
        try:
            answer = input("\n[?] Attempt to install missing tools? (Requires internet, Go, Python3/pip3, Git, potentially sudo/root) [y/N]: ")
            if answer.lower().strip() == 'y': install_confirmed = True
        except EOFError: safe_print("\n[!] Non-interactive environment detected. Cannot prompt.", file=sys.stderr); install_confirmed = False

    if not install_confirmed:
        safe_print("[*] Skipping installation.")
        essential_missing = [t for t in ESSENTIAL_TOOLS if t in missing_tools]
        if essential_missing: safe_print(f"[!] Cannot proceed without essential tools: {', '.join(essential_missing)}", file=sys.stderr); sys.exit(1)
        else: safe_print("[!] Proceeding without optional missing tools."); return False

    safe_print("\n[*] Attempting to install missing tools...")
    safe_print(f"[*] Note: Tools requiring 'sudo' might fail if not run as root. Git clones target '{INSTALL_DIR}'.")
    safe_print("[*] Please run failed commands manually if needed.")

    still_missing = []
    base_deps = ["git", "python3", "pip3", "curl", "go", "ruby"] # Base dependencies
    install_order = [dep for dep in base_deps if dep in missing_tools] + \
                    [tool for tool in missing_tools if tool not in base_deps]

    # Ensure INSTALL_DIR exists and is writable (or skip git clones)
    install_dir_writable = False
    try:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        test_file = os.path.join(INSTALL_DIR, ".recon_write_test")
        with open(test_file, "w") as f: f.write("test")
        os.remove(test_file)
        install_dir_writable = True
    except OSError as e:
        safe_print(f"[!] Warning: Cannot write to INSTALL_DIR ('{INSTALL_DIR}'): {e}", file=sys.stderr)
        safe_print("[!] Git clone installations will be skipped. Please ensure '{INSTALL_DIR}' is writable or run with sudo.", file=sys.stderr)


    for tool in install_order:
        install_cmd = TOOL_INSTALL_CMDS.get(tool)
        if not install_cmd:
            safe_print(f"[!] No automated installation command defined for {tool}. Please install manually.")
            still_missing.append(tool); manual_install_notes.append(f"- {tool}: Install manually.")
            continue

        # Skip git clones if install dir isn't writable
        if "git clone" in install_cmd and not install_dir_writable:
             safe_print(f"[!] Skipping git clone for {tool} due to INSTALL_DIR permissions.")
             still_missing.append(tool); manual_install_notes.append(f"- {tool}: Requires writable INSTALL_DIR ('{INSTALL_DIR}') or manual install.")
             continue

        safe_print(f"\n--- Installing {tool} ---")
        safe_print(f"Running: {install_cmd}")
        # Run the command (might include sudo)
        runner.run(install_cmd, silent=False, capture_output=False, timeout=600) # 10 min timeout

        time.sleep(2) # Give system a moment
        if check_tool_exists(tool):
            safe_print(f"[+] {tool} installed successfully or already present after attempt.")
            # Update TOOL_PATHS if needed (e.g., after go install)
            if tool in ["assetfinder", "waybackurls", "webanalyze", "gau_go", "bbot", "dnsx"]:
                 actual_path = shutil.which(tool.replace("_go","")) # Check actual command name
                 if actual_path: TOOL_PATHS[tool.replace("_go","")] = actual_path
                 elif tool == "bbot": # Check local bin specifically for bbot
                      local_bbot = os.path.expanduser("~/.local/bin/bbot")
                      if os.path.exists(local_bbot): TOOL_PATHS["bbot"] = local_bbot

        else:
            safe_print(f"[!] Failed to automatically install {tool}.")
            safe_print(f"    Consider running manually: {install_cmd}")
            still_missing.append(tool)
            if "sudo" in install_cmd or "Sniper" in install_cmd or "crtsh" in install_cmd: manual_install_notes.append(f"- {tool}: Requires sudo/root or manual script/copy. Try: {install_cmd}")
            else: manual_install_notes.append(f"- {tool}: Failed. Check logs or try manually: {install_cmd}")

    if still_missing:
        safe_print("\n[!] The following tools could not be installed automatically:")
        for tool in still_missing: safe_print(f"  - {tool}")
        if manual_install_notes:
             safe_print("\n[*] Manual Installation Notes:")
             for note in manual_install_notes: safe_print(f"    {note}")
        essential_missing_final = [t for t in ESSENTIAL_TOOLS if t in still_missing]
        if essential_missing_final: safe_print(f"[!] Cannot proceed without essential tools: {', '.join(essential_missing_final)}", file=sys.stderr); sys.exit(1)
        else: safe_print("[!] Proceeding without optional missing tools."); return False
    else:
        safe_print("\n[+] All required tools are now installed or were already present.")
        return True


# --- Recon Functions ---

def run_subdomain_tool(tool_name, config, target, target_recon_base):
    """Runs a single subdomain tool and returns the path to its output file."""
    tool_path_check = config.get("check", TOOL_PATHS.get(tool_name, tool_name))
    dependencies_met = all(check_tool_exists(dep, TOOL_PATHS.get(dep, dep)) for dep in config.get("depends", []))

    if dependencies_met and check_tool_exists(tool_name, tool_path_check):
        cmd = config["cmd"]
        # Handle sudo requirement for bbot
        if tool_name == "bbot" and "sudo" not in cmd:
            if os.geteuid() != 0: cmd = "sudo " + cmd

        output_file = config.get("output_file")
        if output_file:
            make_dir(os.path.dirname(output_file))
            # Add a small delay specifically *before* running bbot if it outputs to a dir
            if tool_name == "bbot": time.sleep(2)
            runner.run(cmd, silent=True, capture_output=False, timeout=1800) # 30 min timeout per tool
            # Add delay *after* running bbot before checking the output file
            if tool_name == "bbot": time.sleep(5)

            # Special handling for bbot directory output
            if tool_name == "bbot" and os.path.isdir(output_file):
                # Use recursive glob to find output.txt OR subdomains.txt in any subdirectory
                bbot_files = glob.glob(os.path.join(output_file, "**", "output.txt"), recursive=True) + \
                             glob.glob(os.path.join(output_file, "**", "subdomains.txt"), recursive=True)
                if bbot_files:
                    # Prioritize output.txt if both exist? Or just take first? Let's take first.
                    bbot_out_txt = next((f for f in bbot_files if "output.txt" in f), None)
                    return bbot_out_txt if bbot_out_txt else bbot_files[0] # Prioritize output.txt
                else:
                    safe_print(f"[!] Could not find 'subdomains.txt' or 'output.txt' within bbot output directory: {output_file}", file=sys.stderr)
                    return None # File not found within bbot dir
            elif os.path.exists(output_file): # Check standard file output
                 return output_file
            else:
                 return None # Tool ran but expected output file doesn't exist
        else: # Handle stdout tools
            results = runner.run(cmd, silent=True, capture_output=True, timeout=1800)
            stdout_file = os.path.join(target_recon_base, f"{tool_name}_stdout.txt")
            write_lines_to_file(stdout_file, results)
            return stdout_file
    # else: safe_print(f"[*] Skipping subdomain tool '{tool_name}' (Not Found or Dependencies Missing)") # Reduce noise
    return None


def enum_subdomains(target, target_recon_base, executor):
    """Runs various subdomain enumeration tools in PARALLEL for a SINGLE target."""
    safe_print(f"[*] Starting parallel subdomain enumeration for: {target}")
    all_raw_output_files = []
    futures = []
    valid_domain_pattern = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    bbot_out_dir = os.path.join(target_recon_base, "bbot_results")

    # Tool Definitions (User Provided)
    file_output_tools = {
        "amass": {"cmd": f"{TOOL_PATHS['amass']} enum -brute -min-for-recursive 2 -d {target} -o {target_recon_base}/amass_subdomains.txt", "output_file": f"{target_recon_base}/amass_subdomains.txt"},
        "subfinder": {"cmd": f"{TOOL_PATHS['subfinder']} -d {target} -o {target_recon_base}/subfinder_subdomains.txt -silent", "output_file": f"{target_recon_base}/subfinder_subdomains.txt"},
        "sublist3r": {"check": TOOL_PATHS['sublist3r'], "cmd": f"{TOOL_PATHS['sublist3r']} -d {target} -o {target_recon_base}/sublist3r_subdomains.txt", "output_file": f"{target_recon_base}/sublist3r_subdomains.txt"},
        "oneforall": {"check": TOOL_PATHS['oneforall'], "cmd": f"python3 {TOOL_PATHS['oneforall']} --target {target} run --path {target_recon_base}/oneforall_results", "output_file": f"{target_recon_base}/oneforall_results/{target}.csv"}, # Output to dir, check csv
        "securitytrails": {"check": "curl", "cmd": f"{TOOL_PATHS['curl']} -s \"https://api.securitytrails.com/v1/domain/{target}/subdomains?children_only=false\" -H \"APIKEY:$SECURITYTRAILS_API_KEY\" | {TOOL_PATHS['jq']} -r '.subdomains[] | \"{{}}.{target}\"' > {target_recon_base}/securitytrails_subdomains.txt", "output_file": f"{target_recon_base}/securitytrails_subdomains.txt", "depends": ["jq"]},
        "assetnote": {"check": "curl", "cmd": f"{TOOL_PATHS['curl']} -s -X GET \"https://api.assetnote.io/v1/targets/{target}/assets?asset_type=domain\" -H \"X-API-Key: $ASSETNOTE_API_KEY\" | {TOOL_PATHS['jq']} -r '.assets[].name' > {target_recon_base}/assetnote_subdomains.txt", "output_file": f"{target_recon_base}/assetnote_subdomains.txt", "depends": ["jq"]},
        "knockpy": {"check": TOOL_PATHS['knockpy'], "cmd": f"{TOOL_PATHS['knockpy']} {target} -o {target_recon_base}/knockpy_results", "output_file": f"{target_recon_base}/knockpy_results/{target}_subdomains.txt"},
        "sudomy": {"check": TOOL_PATHS['sudomy'], "cmd": f"{TOOL_PATHS['sudomy']} -d {target} -o {target_recon_base}/sudomy_results", "output_file": f"{target_recon_base}/sudomy_results/subdomain.txt"},
         # Removed -f list flag from bbot command
        "bbot": {"check": TOOL_PATHS['bbot'], "cmd": f"{TOOL_PATHS['bbot']} -t {target} -p subdomain-enum -o {bbot_out_dir} -y --force", "output_file": bbot_out_dir},
    }
    stdout_tools = {
         "censys": {"check": "censys", "cmd": f"{TOOL_PATHS['censys']} search 'names: {target}' --index-type hosts --fields ip,metadata.os --virtual-hosts INCLUDE --no-color"},
         "assetfinder": {"check": "assetfinder", "cmd": f"{TOOL_PATHS['assetfinder']} --subs-only {target}"},
         "crtsh": {"check": TOOL_PATHS['crtsh'], "cmd": f"{TOOL_PATHS['crtsh']} -d {target} -r"}
    }

    # Submit all tools to the executor
    all_tools_config = {**file_output_tools, **stdout_tools}
    for tool_name, config in all_tools_config.items():
        futures.append(executor.submit(run_subdomain_tool, tool_name, config, target, target_recon_base))

    # Collect results (output file paths) as they complete
    for future in concurrent.futures.as_completed(futures):
        try:
            output_file = future.result()
            if output_file and os.path.exists(output_file): # Check if file exists after run
                all_raw_output_files.append(output_file)
        except Exception as e:
            safe_print(f"[!] Error in subdomain tool future for {target}: {e}", file=sys.stderr)

    # Consolidate results from all generated files
    safe_print(f"[*] Consolidating subdomain results for {target}...")
    all_subs = set()
    domain_pattern_stdout = re.compile(r"([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}") # Re-define for parsing

    for raw_file in all_raw_output_files:
        filename = os.path.basename(raw_file)
        # Infer tool name more robustly for specific parsing
        tool_name = "unknown"
        # Simplified inference based on common patterns
        if "amass" in filename: tool_name = "amass"
        elif "subfinder" in filename: tool_name = "subfinder"
        elif "sublist3r" in filename: tool_name = "sublist3r"
        elif "oneforall" in raw_file: tool_name = "oneforall"
        elif "securitytrails" in filename: tool_name = "securitytrails"
        elif "assetnote" in filename: tool_name = "assetnote"
        elif "knockpy" in raw_file: tool_name = "knockpy"
        elif "sudomy" in raw_file: tool_name = "sudomy"
        elif "bbot" in raw_file: tool_name = "bbot" # Check path for bbot
        elif "censys" in filename: tool_name = "censys"
        elif "assetfinder" in filename: tool_name = "assetfinder"
        elif "crtsh" in filename: tool_name = "crtsh"

        results = read_file_lines(raw_file)
        count = 0
        for line in results:
            sub = None
            # Apply specific parsing/cleaning based on tool if needed
            if tool_name == "oneforall" and ',' in line:
                try: sub = line.split(',')[5].strip() # Index 5 is often the subdomain in OneForAll CSV
                except IndexError: continue
            elif tool_name in ["censys", "assetfinder", "crtsh"]: # Parse potential domains from stdout logs
                 matches = domain_pattern_stdout.findall(line)
                 # Check if match ends with target domain (more reliable)
                 subs_found = {".".join(match).lower() for match in matches if ("." + target) in ("." + "".join(match).lower())}
                 all_subs.update(s for s in subs_found if valid_domain_pattern.match(s))
                 count += len(subs_found)
                 continue # Skip generic processing for these
            elif tool_name == "amass" and "FQDN" in line: # Handle Amass verbose output
                 try: sub = line.split('(FQDN)')[0].strip()
                 except: pass
            else: # Generic handling for simple lists (subfinder, sublist3r, bbot, knockpy, sudomy, etc.)
                sub = line.strip()

            if sub:
                # Generic cleaning
                sub = sub.lower().replace('"', '').replace("'", "").split(':')[0].strip('.')
                # More robust validation: endswith target domain OR is the target domain itself
                if valid_domain_pattern.match(sub) and (sub == target or sub.endswith(f".{target}")):
                    all_subs.add(sub); count += 1

        # if count > 0: safe_print(f"    Read {count} subs from {os.path.basename(raw_file)}") # Reduce noise

    unique_subs_list = sorted(list(all_subs))
    final_subs_file = os.path.join(target_recon_base, f"{target}_subdomains.txt")
    write_lines_to_file(final_subs_file, unique_subs_list)
    safe_print(f"[*] Finished parallel subdomain enumeration for {target}. Found {len(unique_subs_list)} unique valid subdomains.")
    return final_subs_file


def resolve_domains_to_ips(subdomain_file, output_dir):
    """Resolves domains from a file to IPs using dnsx or socket."""
    ip_file = os.path.join(output_dir, "ips_for_scan.txt")
    ip_domain_map_file = os.path.join(output_dir, "ip_to_domain_map.json")
    ip_to_domains = {}
    resolved_ips = set()

    if not os.path.exists(subdomain_file) or os.path.getsize(subdomain_file) == 0:
        safe_print("[!] Subdomain file is empty, cannot resolve IPs.")
        return None, {}

    subdomains = read_file_lines(subdomain_file)
    if not subdomains:
        safe_print("[!] No subdomains read from file, cannot resolve IPs.")
        return None, {}

    safe_print(f"[*] Resolving {len(subdomains)} domains to IP addresses...")

    if check_tool_exists("dnsx", TOOL_PATHS['dnsx']):
        safe_print("[*] Using dnsx for DNS resolution...")
        dnsx_output_file = os.path.join(output_dir, "dnsx_results.json")
        dnsx_cmd = f"{TOOL_PATHS['dnsx']} -l {subdomain_file} -json -o {dnsx_output_file} -silent -a -aaaa -resp"
        runner.run(dnsx_cmd, capture_output=False, timeout=600) # 10 min timeout

        if os.path.exists(dnsx_output_file):
            try:
                with open(dnsx_output_file, 'r') as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            host = data.get("host")
                            ips = data.get("a", []) + data.get("aaaa", [])
                            if host and ips:
                                for ip in ips:
                                    try:
                                        # Validate IP address
                                        ipaddress.ip_address(ip)
                                        resolved_ips.add(ip)
                                        if ip not in ip_to_domains:
                                            ip_to_domains[ip] = []
                                        if host not in ip_to_domains[ip]: # Avoid duplicates per IP
                                            ip_to_domains[ip].append(host)
                                    except ValueError:
                                        pass # Ignore invalid IPs
                        except json.JSONDecodeError:
                            safe_print(f"[!] Error decoding JSON line from dnsx output: {line.strip()}", file=sys.stderr)
                            continue
            except Exception as e:
                safe_print(f"[!] Error reading dnsx output file {dnsx_output_file}: {e}", file=sys.stderr)
        else:
             safe_print("[!] dnsx did not produce an output file. Falling back to socket resolution.")

    # Fallback or if dnsx is not used/failed
    if not resolved_ips:
        safe_print("[*] Using socket.gethostbyname_ex for DNS resolution (slower)...")
        for domain in subdomains:
            try:
                hostname, aliaslist, ipaddrlist = socket.gethostbyname_ex(domain)
                for ip in ipaddrlist:
                    try:
                        ipaddress.ip_address(ip) # Validate
                        resolved_ips.add(ip)
                        if ip not in ip_to_domains: ip_to_domains[ip] = []
                        if domain not in ip_to_domains[ip]: ip_to_domains[ip].append(domain)
                        if hostname != domain and hostname not in ip_to_domains[ip]:
                             ip_to_domains[ip].append(hostname)
                    except ValueError: pass # Ignore invalid IPs
            except socket.gaierror: pass
            except Exception as e: safe_print(f"[!] Error resolving domain {domain}: {e}", file=sys.stderr)

    if resolved_ips:
        safe_print(f"[+] Resolved {len(subdomains)} domains to {len(resolved_ips)} unique IP addresses.")
        write_lines_to_file(ip_file, list(resolved_ips))
        try:
            with open(ip_domain_map_file, 'w') as f:
                json.dump(ip_to_domains, f, indent=4)
            safe_print(f"[+] IP-to-Domain mapping saved to: {ip_domain_map_file}")
        except Exception as e: safe_print(f"[!] Error writing IP-to-Domain map: {e}", file=sys.stderr)
        return ip_file, ip_to_domains
    else:
        safe_print("[!] Failed to resolve any domains to IP addresses.")
        return None, {}


def run_nmap_scan_on_host(host, ports_str, output_dir):
    """Runs Nmap -sCV on a single host for specific ports."""
    safe_hostname = re.sub(r'[^\w\-.]', '_', host)
    nmap_sv_scan_norm = os.path.join(output_dir, f"nmap_sv_{safe_hostname}.nmap")
    nmap_sv_scan_xml = os.path.join(output_dir, f"nmap_sv_{safe_hostname}.xml")
    nmap_cmd = f"{TOOL_PATHS['nmap']} -sCV -Pn -p T:{ports_str} {host} -oN {nmap_sv_scan_norm} -oX {nmap_sv_scan_xml} -T4"
    # Increased Nmap timeout to 3 hours
    runner.run(nmap_cmd, capture_output=False, timeout=LONG_TIMEOUT)
    return host, nmap_sv_scan_norm, nmap_sv_scan_xml


def run_port_scans_parallel(ip_file, output_dir, executor, ip_domain_map):
    """Runs Masscan for discovery, then Nmap -sCV in parallel for service enumeration."""
    safe_print(f"[*] Starting Port Scans (Masscan + Nmap) on IPs in: {ip_file}")
    if not ip_file or not os.path.exists(ip_file) or os.path.getsize(ip_file) == 0:
        safe_print("[!] Skipping Port Scans: IP file empty or missing.")
        return {}
    if not check_tool_exists("masscan", TOOL_PATHS['masscan']): return {}
    if not check_tool_exists("nmap", TOOL_PATHS['nmap']): return {}

    make_dir(output_dir)
    masscan_json_output = os.path.join(output_dir, "masscan_results.json")
    nmap_results_dir = os.path.join(output_dir, "nmap_host_results") # Dir for individual host scans
    make_dir(nmap_results_dir)

    # --- Step 1: Run Masscan ---
    # Determine source IP for Masscan
    source_ip = get_local_ip()
    source_ip_flag = f"--source-ip {source_ip}" if source_ip else ""

    masscan_cmd = f"{TOOL_PATHS['masscan']} -iL {ip_file} -p1-65535 --rate 1000 {source_ip_flag} --wait 0 -oJ {masscan_json_output}"
    if os.geteuid() != 0: masscan_cmd = "sudo " + masscan_cmd
    safe_print("[*] Port Scan: Running Masscan for initial discovery...")
    runner.run(masscan_cmd, capture_output=False, timeout=3600) # 1 hour timeout for masscan is usually sufficient

    # --- Step 2: Parse Masscan JSON Output ---
    host_ports = {} # Dictionary to store {host_ip: [port1, port2,...]}
    if not os.path.exists(masscan_json_output) or os.path.getsize(masscan_json_output) == 0:
        safe_print("[!] Masscan did not produce results. Skipping Nmap service scan.")
        return {"masscan_output": masscan_json_output}

    safe_print("[*] Port Scan: Parsing Masscan results...")
    try:
        with open(masscan_json_output, 'r') as f:
            content = f.read().strip()
            if content.startswith('[') and content.endswith(']'): masscan_data = json.loads(content)
            elif content: masscan_data = [json.loads(line) for line in content.splitlines() if line.strip()]
            else: masscan_data = []

        for item in masscan_data:
            ip = item.get("ip")
            port_info = item.get("ports", [{}])[0]
            port = port_info.get("port")
            proto = port_info.get("proto", "tcp")
            if ip and port and proto == "tcp":
                if ip not in host_ports: host_ports[ip] = set()
                host_ports[ip].add(str(port))
    except json.JSONDecodeError as e:
        safe_print(f"[!] Error parsing Masscan JSON output {masscan_json_output}: {e}", file=sys.stderr)
        return {"masscan_output": masscan_json_output}
    except Exception as e:
        safe_print(f"[!] Unexpected error processing Masscan results: {e}", file=sys.stderr)
        return {"masscan_output": masscan_json_output}

    if not host_ports:
        safe_print("[*] Masscan did not find any open TCP ports.")
        return {"masscan_output": masscan_json_output}

    safe_print(f"[*] Masscan identified {len(host_ports)} hosts with open TCP ports.")

    # --- Step 3: Run Nmap -sCV in Parallel ---
    safe_print(f"[*] Port Scan: Submitting Nmap -sCV scans for {len(host_ports)} hosts...")
    nmap_futures = []
    for host_ip, ports in host_ports.items():
        target_host = host_ip # Use IP for Nmap target
        ports_str = ",".join(sorted(list(ports), key=int)) # Create comma-separated string
        future = executor.submit(run_nmap_scan_on_host, target_host, ports_str, nmap_results_dir)
        nmap_futures.append(future)

    # --- Step 4: Collect Nmap Results ---
    nmap_xml_files = []
    nmap_norm_files = []
    for future in concurrent.futures.as_completed(nmap_futures):
        try:
            host, norm_file, xml_file = future.result()
            if os.path.exists(xml_file) and os.path.getsize(xml_file) > 0: nmap_xml_files.append(xml_file)
            if os.path.exists(norm_file) and os.path.getsize(norm_file) > 0: nmap_norm_files.append(norm_file)
        except Exception as e: safe_print(f"[!] Error collecting Nmap results for a host: {e}", file=sys.stderr)

    safe_print(f"[*] Nmap scans complete. Individual results in: {nmap_results_dir}")

    return {
        "masscan_output": masscan_json_output,
        "nmap_results_dir": nmap_results_dir,
        "nmap_xml_files": nmap_xml_files,
        "nmap_norm_files": nmap_norm_files
    }


def run_httprobe(input_file, output_file):
    """Runs httprobe to find live web servers."""
    safe_print(f"[*] Running httprobe on hosts/domains in: {input_file}")
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0: return None
    if not check_tool_exists("httprobe", TOOL_PATHS['httprobe']): return None
    # Increased timeout to 10s (-t 10000) and reduced concurrency to 30 (-c 30)
    httprobe_cmd = f"cat {input_file} | {TOOL_PATHS['httprobe']} -c 30 -t 10000"
    alive_hosts = runner.run(httprobe_cmd)
    cleaned_alive = sorted(list(set(filter(None, [host.strip() for host in alive_hosts]))))
    write_lines_to_file(output_file, cleaned_alive)
    if not cleaned_alive: safe_print("[!] httprobe did not find any live web servers.")
    else: safe_print(f"[*] Found {len(cleaned_alive)} live web servers via httprobe.")
    return output_file

# --- Functions to be run in parallel --- (Wrappers remain the same)
def run_generic_tool_wrapper(tool_name, command, output_file=None, check_file_content=True, tool_check_cmd=None, timeout=None):
    """Generic wrapper to run a tool, check for its existence, and optionally check output file."""
    # ... (No changes needed from previous version) ...
    tool_check = tool_check_cmd if tool_check_cmd else TOOL_PATHS.get(tool_name, tool_name)
    if not check_tool_exists(tool_name, tool_check): return tool_name, None
    runner.run(command, capture_output=False, timeout=timeout)
    if output_file:
        if os.path.exists(output_file) and (not check_file_content or os.path.getsize(output_file) > 0): return tool_name, output_file
        else:
            if check_file_content and os.path.exists(output_file):
                try: os.remove(output_file)
                except OSError: pass
            return tool_name, None
    else: return tool_name, "executed"

def run_takeover_tool(tool_name, command, output_file):
    """Wrapper for takeover tools."""
    # ... (No changes needed from previous version) ...
    return run_generic_tool_wrapper(tool_name, command, output_file, check_file_content=True, tool_check_cmd=TOOL_PATHS.get(tool_name, tool_name), timeout=600)

def run_web_scan_tool(tool_name, command, expected_output=None, tool_check_cmd=None, timeout=None):
    """Wrapper for web scan tools, handling file or directory output."""
    # ... (No changes needed from previous version) ...
    tool_check = tool_check_cmd if tool_check_cmd else TOOL_PATHS.get(tool_name, tool_name)
    if not check_tool_exists(tool_name, tool_check): return tool_name, None
    runner.run(command, capture_output=False, timeout=timeout)
    output_path = None
    if expected_output:
        time.sleep(1)
        if os.path.exists(expected_output):
             if os.path.isfile(expected_output) and os.path.getsize(expected_output) > 0: output_path = expected_output
             elif os.path.isdir(expected_output):
                 if tool_name == "eyewitness":
                     ew_report = glob.glob(os.path.join(expected_output, "report.html"))
                     if ew_report: output_path = ew_report[0]
                 elif tool_name == "dirsearch":
                      dir_items = glob.glob(os.path.join(expected_output, "dirsearch_report_*.txt"))
                      if dir_items: output_path = expected_output
                 elif tool_name == "gospider":
                      if os.listdir(expected_output): output_path = expected_output
                 elif os.listdir(expected_output): output_path = expected_output
    if not output_path and expected_output and os.path.isfile(expected_output) and os.path.exists(expected_output) and os.path.getsize(expected_output) == 0:
        try: os.remove(expected_output)
        except OSError: pass
    return tool_name, output_path

def run_js_gau_on_host(host_url, js_scanner_path, gau_path):
    """Runs JS-Scan and GAU for a single host."""
    # ... (No changes needed from previous version) ...
    results = {'host': host_url, 'js_links': [], 'gau_links': []}
    js_scanner_exists = js_scanner_path and check_tool_exists("js-scanner", js_scanner_path)
    gau_exists = gau_path and check_tool_exists("gau", gau_path)
    if js_scanner_exists:
        js_cmd = f"{js_scanner_path} -u {host_url} -o cli"
        js_links = runner.run(js_cmd, silent=True, timeout=300)
        if js_links: results['js_links'] = [link.strip() for link in js_links if link.strip()]
    if gau_exists:
        try:
            domain_for_gau = host_url.split('://')[1].split('/')[0].split(':')[0]
            gau_cmd = f"{gau_path} --subs {domain_for_gau}"
            gau_links = runner.run(gau_cmd, silent=True, timeout=300)
            if gau_links: results['gau_links'] = [link.strip() for link in gau_links if link.strip()]
        except IndexError: safe_print(f"[!] Could not extract domain for GAU from: {host_url}", file=sys.stderr)
    return results

def run_wappalyzer_on_host(host_url, output_jsonl_file, lock):
    """Runs Wappalyzer via Docker on a single host and appends to JSONL."""
    # ... (No changes needed from previous version) ...
    wapp_cmd = f"{TOOL_PATHS['docker']} run --rm wappalyzer/cli {host_url} --quiet --no-wait"
    wapp_output_lines = runner.run(wapp_cmd, silent=True, timeout=300)
    if wapp_output_lines:
        with lock:
            try:
                with open(output_jsonl_file, 'a', encoding='utf-8') as f_out:
                    for line in wapp_output_lines:
                        try: json.loads(line); f_out.write(line.strip() + "\n")
                        except json.JSONDecodeError: safe_print(f"[!] Wappalyzer invalid JSON for {host_url}: {line[:100]}...", file=sys.stderr)
                return True
            except Exception as e: safe_print(f"[!] Error writing Wappalyzer output for {host_url}: {e}", file=sys.stderr); return False
    return False

def run_cms_scan_on_host(host_url, output_dir, today_date):
    """Runs WPScan on a single host."""
    results = {}
    wpscan_output = os.path.join(output_dir, f"wpscan_{host_url.split('://')[1]}_{today_date}.txt")
    if check_tool_exists("wpscan", TOOL_PATHS['wpscan']):
        # Added sudo
        cmd = f"sudo {TOOL_PATHS['wpscan']} --url {host_url} --output {wpscan_output} --format cli-no-color --random-user-agent --disable-tls-checks --batch"
        name, out_path = run_generic_tool_wrapper("wpscan", cmd, wpscan_output, tool_check_cmd=TOOL_PATHS['wpscan'], timeout=1800)
        if out_path: results[name] = out_path
    return host_url, results

def run_s3_bucket_check(bucket_name, output_dir):
    """Runs S3Scanner and AWSBucketDump against a single potential bucket name."""
    # ... (No changes needed from previous version) ...
    results = {}
    s3scanner_output = os.path.join(output_dir, f"s3scanner_{bucket_name}.txt")
    s3_tool_path = TOOL_PATHS.get('s3scanner', 's3scanner')
    s3_cmd = None
    if check_tool_exists("S3Scanner Command", "s3scanner"): s3_cmd = f"s3scanner scan --bucket {bucket_name}"
    elif check_tool_exists("S3Scanner Script", s3_tool_path) and s3_tool_path.endswith(".py"): s3_cmd = f"python3 {s3_tool_path} scan --bucket {bucket_name}"
    if s3_cmd:
        s3_lines = runner.run(s3_cmd, silent=True, timeout=120)
        findings = [line for line in s3_lines if "Public bucket found" in line or "WRITE ACL" in line or "READ ACL" in line or "Directory listing enabled" in line]
        if findings: write_lines_to_file(s3scanner_output, findings); results["S3Scanner"] = s3scanner_output
    awsdump_output = os.path.join(output_dir, f"awsbucketdump_{bucket_name}.txt")
    awsdump_tool_path = TOOL_PATHS.get('awsbucketdump', 'awsbucketdump')
    awsdump_cmd = None
    if check_tool_exists("AWSBucketDump Command", "awsbucketdump"): awsdump_cmd = f"awsbucketdump -b {bucket_name}"
    elif check_tool_exists("AWSBucketDump Script", awsdump_tool_path) and awsdump_tool_path.endswith(".py"): awsdump_cmd = f"python3 {awsdump_tool_path} -b {bucket_name}"
    if awsdump_cmd:
        dump_lines = runner.run(awsdump_cmd, silent=True, timeout=120)
        filtered_lines = [line for line in dump_lines if "NoSuchBucket" not in line and "AccessDenied" not in line and "doesn't exist" not in line and line.strip()]
        if filtered_lines: write_lines_to_file(awsdump_output, filtered_lines); results["AWSBucketDump"] = awsdump_output
    return bucket_name, results

# --- Main Recon Functions (Using TOOL_PATHS dictionary) ---

def run_subdomain_takeover_parallel(subs_file, output_dir, executor):
    """Runs subdomain takeover tools in parallel."""
    # ... (No changes needed from previous version) ...
    safe_print(f"[*] Checking for potential subdomain takeovers (in parallel) on list: {subs_file}")
    if not os.path.exists(subs_file) or os.path.getsize(subs_file) == 0: return {}
    make_dir(output_dir); results = {}; futures = []
    tools_to_run = {
        "subjack": {"cmd": f"{TOOL_PATHS['subjack']} -w {subs_file} -t 50 -ssl -c {TOOL_PATHS['subjack_fingerprints']} -v -o {output_dir}/subjack.txt", "output": f"{output_dir}/subjack.txt"},
        "nuclei_takeover": {"cmd": f"{TOOL_PATHS['nuclei']} -l {subs_file} -t takeover -o {output_dir}/nuclei_takeovers.txt -severity critical,high,medium", "output": f"{output_dir}/nuclei_takeovers.txt"}
    }
    for tool, config in tools_to_run.items(): futures.append(executor.submit(run_takeover_tool, tool, config["cmd"], config["output"]))
    for future in concurrent.futures.as_completed(futures):
        try:
            tool_name, output_file = future.result()
            if output_file: results[tool_name] = output_file
        except Exception as e: safe_print(f"[!] Error in takeover tool future: {e}", file=sys.stderr)
    return results

def run_web_scans_parallel(alive_file, output_base_dir, executor):
    """Runs Eyewitness, Nuclei (non-takeover), Waybackurls, Nikto, Spider concurrently."""
    # ... (No changes needed from previous version) ...
    safe_print(f"[*] Starting web scans (Eyewitness, Nuclei, Wayback, Nikto, Spider) concurrently on: {alive_file}")
    if not os.path.exists(alive_file) or os.path.getsize(alive_file) == 0: return {}
    results = {}; futures = []; make_dir(output_base_dir)
    eyewitness_dir = os.path.join(output_base_dir, "eyewitness"); make_dir(eyewitness_dir)
    eyewitness_cmd = f"{TOOL_PATHS['eyewitness']} --web -f {alive_file} -d {eyewitness_dir} --no-prompt --timeout 60"
    futures.append(executor.submit(run_web_scan_tool, "eyewitness", eyewitness_cmd, eyewitness_dir, tool_check_cmd=TOOL_PATHS['eyewitness'], timeout=1800))
    nuclei_output_file = os.path.join(output_base_dir, "nuclei_scan_report.txt")
    nuclei_cmd = f"{TOOL_PATHS['nuclei']} -l {alive_file} -etags takeover,cms -severity critical,high,medium,low,info -stats -o {nuclei_output_file}"
    # Increased Nuclei timeout to 3 hours
    futures.append(executor.submit(run_web_scan_tool, "nuclei_general", nuclei_cmd, nuclei_output_file, tool_check_cmd=TOOL_PATHS['nuclei'], timeout=LONG_TIMEOUT))
    wayback_dir = os.path.join(output_base_dir, "wayback"); make_dir(wayback_dir)
    wayback_all_urls_file = os.path.join(wayback_dir, "wayback_all_urls.txt")
    wayback_cmd = f"cat {alive_file} | {TOOL_PATHS['waybackurls']} > {wayback_all_urls_file}"
    futures.append(executor.submit(run_web_scan_tool, "waybackurls", wayback_cmd, wayback_all_urls_file, tool_check_cmd=TOOL_PATHS['waybackurls'], timeout=1800))
    nikto_output_file = os.path.join(output_base_dir, "nikto_scan_report.txt")
    nikto_cmd = f"{TOOL_PATHS['nikto']} -h {alive_file} -Tuning 1,2,3,4,5,x -Format txt -output {nikto_output_file} -ask no"
    # Increased Nikto timeout to 3 hours
    futures.append(executor.submit(run_web_scan_tool, "nikto", nikto_cmd, nikto_output_file, tool_check_cmd=TOOL_PATHS['nikto'], timeout=LONG_TIMEOUT))
    spider_output_dir = os.path.join(output_base_dir, "gospider"); make_dir(spider_output_dir)
    gospider_cmd = f"{TOOL_PATHS['gospider']} -S {alive_file} -o {spider_output_dir} -c 10 -t 20 -d 3 --other-source --include-subs" # Use -S for file input
    futures.append(executor.submit(run_web_scan_tool, "gospider", gospider_cmd, spider_output_dir, tool_check_cmd=TOOL_PATHS['gospider'], timeout=1800))
    temp_results = {}
    for future in concurrent.futures.as_completed(futures):
        try:
            tool_name, output_path = future.result()
            if output_path: temp_results[tool_name] = output_path
        except Exception as e: safe_print(f"[!] Error in web scan future ({tool_name}): {e}", file=sys.stderr)
    if "waybackurls" in temp_results and temp_results["waybackurls"]:
        results["wayback_urls"] = temp_results["waybackurls"]
        safe_print("[*] Analyzing Waybackurls output...")
        wayback_output = read_file_lines(results["wayback_urls"])
        if wayback_output:
            wayback_params_file = os.path.join(wayback_dir, "wayback_params.txt")
            wayback_extensions_file = os.path.join(wayback_dir, "wayback_extensions.txt")
            params = set(); param_pattern = re.compile(r'[\?&]([^=]+)=')
            for url in wayback_output: params.update(param_pattern.findall(url))
            if params: write_lines_to_file(wayback_params_file, sorted(list(params))); results["wayback_params"] = wayback_params_file
            extensions = set(); ext_pattern = re.compile(r'\.([a-zA-Z0-9]+)(?:[\?#]|$)')
            for url in wayback_output:
                 path_part = url.split('?')[0].split('#')[0]
                 if '.' in path_part:
                     potential_ext = path_part.split('.')[-1].lower()
                     if potential_ext and len(potential_ext) < 8 and potential_ext.isalnum(): extensions.add(potential_ext)
            if extensions: write_lines_to_file(wayback_extensions_file, sorted(list(extensions))); results["wayback_extensions"] = wayback_extensions_file
    if "eyewitness" in temp_results and temp_results["eyewitness"]: results["eyewitness_report"] = temp_results["eyewitness"]
    if "nuclei_general" in temp_results and temp_results["nuclei_general"]: results["nuclei_report"] = temp_results["nuclei_general"]
    if "nikto" in temp_results and temp_results["nikto"]: results["nikto_report"] = temp_results["nikto"]
    if "gospider" in temp_results and temp_results["gospider"]: results["gospider_output_dir"] = temp_results["gospider"]
    safe_print("[*] Web scans complete.")
    return results

def run_cms_scans_parallel(alive_file, output_dir, executor):
    """Runs CMS scans (WPScan etc.) in parallel for each live host."""
    # ... (No changes needed from previous version) ...
    safe_print(f"[*] Starting CMS scans (in parallel per host) on: {alive_file}")
    if not os.path.exists(alive_file) or os.path.getsize(alive_file) == 0: return {}
    make_dir(output_dir); today_date = datetime.date.today().isoformat()
    alive_hosts = read_file_lines(alive_file); futures = []; results_dict = {}
    for host_url in alive_hosts:
        if host_url.startswith("http"): futures.append(executor.submit(run_cms_scan_on_host, host_url, output_dir, today_date))
    for future in concurrent.futures.as_completed(futures):
        try:
            host_url, host_results = future.result()
            if host_results: results_dict[host_url] = host_results
        except Exception as e: safe_print(f"[!] Error in CMS scan future: {e}", file=sys.stderr)
    return {"cms_scan_output_dir": output_dir, "cms_scan_details": results_dict}

def run_s3_bucket_checks_parallel(subdomain_file, output_dir, executor):
    """Derives potential S3 bucket names and checks them in parallel."""
    # ... (No changes needed from previous version) ...
    safe_print("[*] Starting S3 bucket checks (derived names, parallel)...")
    if not os.path.exists(subdomain_file) or os.path.getsize(subdomain_file) == 0: return {}
    make_dir(output_dir); subdomains = read_file_lines(subdomain_file); potential_buckets = set()
    for sub in subdomains:
        parts = sub.split('.');
        if len(parts) >= 2:
            domain = parts[-2] + '.' + parts[-1]
            potential_buckets.add(domain); potential_buckets.add(parts[-2])
            potential_buckets.add(sub); potential_buckets.add(sub.replace('.', '-'))
            potential_buckets.add(domain.replace('.', '-'))
    valid_bucket_pattern = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
    valid_buckets = {b for b in potential_buckets if valid_bucket_pattern.match(b) and '..' not in b and not b.endswith('-')}
    if not valid_buckets: safe_print("[*] No potential S3 bucket names derived."); return {}
    safe_print(f"[*] Derived {len(valid_buckets)} potential S3 bucket names for checking.")
    futures = []; results_dict = {}
    for bucket in valid_buckets: futures.append(executor.submit(run_s3_bucket_check, bucket, output_dir))
    for future in concurrent.futures.as_completed(futures):
        try:
            bucket_name, bucket_results = future.result()
            if bucket_results: results_dict[bucket_name] = bucket_results
        except Exception as e: safe_print(f"[!] Error in S3 check future: {e}", file=sys.stderr)
    return {"s3_check_output_dir": output_dir, "s3_check_details": results_dict}

def run_js_and_gau_parallel(alive_file, output_dir, executor):
    """Runs JS analysis and GAU in parallel for each live host."""
    # ... (No changes needed from previous version) ...
    safe_print(f"[*] Starting JS-Scan and GAU (in parallel per host) on: {alive_file}")
    if not os.path.exists(alive_file) or os.path.getsize(alive_file) == 0: return {}
    make_dir(output_dir); combined_links_file = os.path.join(output_dir, "js_gau_combined_links.txt")
    results = {}; alive_hosts = read_file_lines(alive_file); all_links = set(); futures = []
    js_scanner_exists = check_tool_exists("js-scanner", TOOL_PATHS['js-scanner'])
    gau_exists = check_tool_exists("gau", TOOL_PATHS['gau'])
    for host_url in alive_hosts: futures.append(executor.submit(run_js_gau_on_host, host_url, TOOL_PATHS['js-scanner'] if js_scanner_exists else None, TOOL_PATHS['gau'] if gau_exists else None))
    for future in concurrent.futures.as_completed(futures):
        try:
            host_result = future.result(); all_links.update(host_result['js_links']); all_links.update(host_result['gau_links'])
        except Exception as e: safe_print(f"[!] Error in JS/GAU future: {e}", file=sys.stderr)
    if all_links:
        unique_links_list = sorted(list(all_links)); write_lines_to_file(combined_links_file, unique_links_list); results["js_gau_links"] = combined_links_file
    return results

def run_tech_fingerprint_parallel(alive_file, output_dir, executor):
    """Runs technology fingerprinting tools (Wappalyzer in parallel, Webanalyze)."""
    # ... (No changes needed from previous version) ...
    safe_print(f"[*] Starting Technology Fingerprinting (partially parallel) on: {alive_file}")
    if not os.path.exists(alive_file) or os.path.getsize(alive_file) == 0: return {}
    make_dir(output_dir); results = {}; alive_hosts = read_file_lines(alive_file); futures = []
    wappalyzer_output_jsonl = os.path.join(output_dir, "wappalyzer_results.jsonl"); wappalyzer_lock = threading.Lock()
    if check_tool_exists("docker", TOOL_PATHS['docker']):
        with open(wappalyzer_output_jsonl, 'w') as f_out: pass
        for host_url in alive_hosts: futures.append(executor.submit(run_wappalyzer_on_host, host_url, wappalyzer_output_jsonl, wappalyzer_lock))
        wapp_success_count = 0
        for future in concurrent.futures.as_completed(futures):
            try:
                if future.result(): wapp_success_count += 1
            except Exception as e: safe_print(f"[!] Error in Wappalyzer future: {e}", file=sys.stderr)
        if os.path.exists(wappalyzer_output_jsonl) and os.path.getsize(wappalyzer_output_jsonl) > 0: results["wappalyzer_report"] = wappalyzer_output_jsonl
        if os.path.exists(wappalyzer_output_jsonl) and os.path.getsize(wappalyzer_output_jsonl) == 0:
             try: os.remove(wappalyzer_output_jsonl)
             except OSError: pass
    webanalyze_output_json = os.path.join(output_dir, "webanalyze_results.json")
    if check_tool_exists("webanalyze", TOOL_PATHS['webanalyze']):
         webanalyze_input_file = os.path.join(output_dir, "_temp_webanalyze_input.txt")
         write_lines_to_file(webanalyze_input_file, alive_hosts)
         runner.run(f"{TOOL_PATHS['webanalyze']} -update", silent=True)
         webanalyze_cmd = f"{TOOL_PATHS['webanalyze']} -hosts {webanalyze_input_file} -crawl 1 -output json {webanalyze_output_json}"
         runner.run(webanalyze_cmd, capture_output=False, timeout=1800)
         if os.path.exists(webanalyze_input_file):
             try: os.remove(webanalyze_input_file)
             except OSError: pass
         if os.path.exists(webanalyze_output_json) and os.path.getsize(webanalyze_output_json) > 0: results["webanalyze_report"] = webanalyze_output_json
         if os.path.exists(webanalyze_output_json) and os.path.getsize(webanalyze_output_json) == 0:
             try: os.remove(webanalyze_output_json)
             except OSError: pass
    return results

def run_misc_tools_parallel(alive_file, subdomain_file, output_dir, executor):
    """Runs miscellaneous tools (Dirsearch, Corsy, Sniper) concurrently."""
    safe_print(f"[*] Starting Miscellaneous Scans (Dirsearch, Corsy, Sniper) concurrently...")
    if not os.path.exists(alive_file) or os.path.getsize(alive_file) == 0: return {}
    make_dir(output_dir); results = {}; futures = []
    dirsearch_output_base = os.path.join(output_dir, "dirsearch"); make_dir(dirsearch_output_base)
    dirsearch_cmd = f"{TOOL_PATHS['dirsearch']} -L {alive_file} --output={dirsearch_output_base}/dirsearch_report_%host.txt --format=simple --force-recursive --exclude-status=404,403,500-599 -t {DEFAULT_MAX_WORKERS}"
    futures.append(executor.submit(run_web_scan_tool, "dirsearch", dirsearch_cmd, dirsearch_output_base, tool_check_cmd=TOOL_PATHS['dirsearch'], timeout=7200))
    corsy_output_file = os.path.join(output_dir, "corsy_scan.txt"); corsy_cmd = None
    # Corrected Corsy command flag from -l to -i
    if check_tool_exists("corsy.py", TOOL_PATHS['corsy']): corsy_cmd = f"python3 {TOOL_PATHS['corsy']} -i {alive_file} -t 20 -o {corsy_output_file}"
    elif check_tool_exists("corsy", "corsy"): corsy_cmd = f"corsy -i {alive_file} -t 20 -o {corsy_output_file}"
    if corsy_cmd: futures.append(executor.submit(run_generic_tool_wrapper, "corsy", corsy_cmd, corsy_output_file, tool_check_cmd=TOOL_PATHS['corsy'], timeout=600))
    sniper_output_file = os.path.join(output_dir, "sniper_dns_report.txt")
    sniper_cmd = f"{TOOL_PATHS['sniper']} -f {subdomain_file}  -m massvulnscan -w test > {sniper_output_file}" # User provided flags
    # Increased Sniper timeout to 3 hours
    futures.append(executor.submit(run_generic_tool_wrapper, "sniper", sniper_cmd, sniper_output_file, tool_check_cmd=TOOL_PATHS['sniper'], timeout=LONG_TIMEOUT))
    for future in concurrent.futures.as_completed(futures):
        try:
            tool_name, output_path = future.result()
            if output_path:
                if tool_name == "dirsearch": results["dirsearch_reports_dir"] = output_path
                elif tool_name == "corsy": results["corsy_report"] = output_path
                elif tool_name == "sniper": results["sniper_report"] = output_path
        except Exception as e: safe_print(f"[!] Error in misc tool future ({tool_name}): {e}", file=sys.stderr)
    safe_print("[*] Miscellaneous Scans complete.")
    return results

def run_secrets_scans(scan_target_path, output_dir):
    """Runs secrets scanning tools sequentially."""
    # ... (No changes needed from previous version) ...
    safe_print(f"[*] Starting Secrets Scans on target path: {scan_target_path}")
    if not scan_target_path or not os.path.isdir(scan_target_path): return {}
    make_dir(output_dir); results = {}
    tools = {
        "git-secrets": {"check": "git", "cmd": f"git secrets --scan --recursive {scan_target_path}", "output_file": f"{output_dir}/git_secrets_scan.txt"},
        "gitleaks": {"check": TOOL_PATHS['gitleaks'], "cmd": f"{TOOL_PATHS['gitleaks']} detect --source {scan_target_path} --report-path {output_dir}/gitleaks_report.json --report-format json -v", "output_file": f"{output_dir}/gitleaks_report.json"},
        "trufflehog": {"check": TOOL_PATHS['trufflehog'], "cmd": f"{TOOL_PATHS['trufflehog']} filesystem {scan_target_path} --json > {output_dir}/trufflehog_report.json", "output_file": f"{output_dir}/trufflehog_report.json"}
    }
    for tool, config in tools.items():
         tool_check_path = config.get("check", TOOL_PATHS.get(tool, tool))
         if check_tool_exists(tool, tool_check_path):
             safe_print(f"--- [Secrets] Running {tool} ---")
             if tool == "git-secrets":
                 secrets_output = runner.run(config["cmd"], silent=False, timeout=1800)
                 if secrets_output: write_lines_to_file(config["output_file"], secrets_output); results[tool] = config["output_file"]
             else:
                 runner.run(config["cmd"], capture_output=False, timeout=1800)
                 if os.path.exists(config["output_file"]) and os.path.getsize(config["output_file"]) > 0: results[tool] = config["output_file"]
                 else:
                     if os.path.exists(config["output_file"]):
                         try: os.remove(config["output_file"])
                         except OSError: pass
    return results

# --- HTML Reporting (Corrected Version - Handles NoneType) ---

def generate_html_report(report_file, report_data, current_phase="Initializing"):
    """Generates a basic HTML report from the collected data, indicating current phase."""
    # safe_print(f"[*] Generating HTML report (Phase: {current_phase})...") # Reduce noise

    # --- Helper Functions ---
    def create_link(path, base_dir):
        """Creates a relative HTML link safely."""
        if not path or not base_dir: return "N/A"
        try:
            abs_base_dir = os.path.abspath(os.path.dirname(report_file))
            abs_path = os.path.abspath(path)
            rel_path = os.path.relpath(abs_path, start=abs_base_dir).replace("\\", "/")
            link_text = os.path.basename(path) or os.path.basename(os.path.dirname(path))
            link_text = re.sub(r'[<>:"/\\|?*]', '_', link_text) # Basic sanitization
            return f'<a href="{rel_path}" target="_blank">{link_text}</a>'
        except ValueError: return f'{path} (Absolute Path)'
        except Exception as e:
            # safe_print(f"[!] Error creating link for {path}: {e}", file=sys.stderr) # Reduce noise
            return f'{path} (Error creating link)'

    def count_lines(filepath):
        """Counts non-empty lines in a file."""
        if not filepath or not os.path.exists(filepath): return 0
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return sum(1 for line in f if line.strip())
        except Exception: return 0

    def parse_nmap_xml_summary(xml_file_or_dir):
        """Parses Nmap XML (single file or multiple in dir) to create an HTML summary."""
        summary = ""
        xml_files = []
        if not xml_file_or_dir: return "Nmap XML/Dir not specified."

        # Handle directory input (from masscan->nmap flow)
        if os.path.isdir(xml_file_or_dir):
            xml_files = glob.glob(os.path.join(xml_file_or_dir, "nmap_sv_*.xml"))
        elif os.path.isfile(xml_file_or_dir):
            xml_files = [xml_file_or_dir]
        else:
            return f"Nmap XML/Dir not found at: {xml_file_or_dir}"

        if not xml_files:
             return "No Nmap XML files found for summary."

        total_hosts_scanned = 0
        all_open_ports = {} # host -> {port/proto: service_string}

        for xml_file in xml_files:
            try:
                tree = ET.parse(xml_file); root = tree.getroot()
                host_count = 0; open_ports = {}
                for host in root.findall('host'):
                    host_count += 1; addr_elem = host.find('address'); addr = addr_elem.get('addr') if addr_elem is not None else 'N/A'
                    hostname_elem = host.find('hostnames/hostname'); hostname = hostname_elem.get('name') if hostname_elem is not None else addr
                    ports = {}; ports_elem = host.find('ports')
                    if ports_elem is not None:
                        for port in ports_elem.findall('port'):
                            state_elem = port.find('state')
                            if state_elem is not None and state_elem.get('state') == 'open':
                                proto = port.get('protocol'); portid = port.get('portid'); service_elem = port.find('service')
                                service = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                                product = service_elem.get('product', '') if service_elem is not None else ''
                                version = service_elem.get('version', '') if service_elem is not None else ''
                                script_elem = port.find('script'); script_output = script_elem.get('output', '').strip() if script_elem is not None else ''
                                service_str = f"{portid}/{proto} ({service} {product} {version}".strip()
                                if script_output: service_str += f" Script: {script_output[:50]}..."
                                service_str += ")"
                                ports[f"{portid}/{proto}"] = service_str # Use port/proto as key
                    # Store ports found for this host, even if hostname couldn't be resolved
                    # Prioritize hostname if available, else use IP
                    display_host = hostname if hostname != addr else addr
                    if ports:
                        if display_host not in all_open_ports:
                             all_open_ports[display_host] = {}
                        all_open_ports[display_host].update(ports) # Merge ports if host seen in multiple files

                total_hosts_scanned += host_count # Accumulate hosts scanned from this file
            except ET.ParseError: summary += f"<span class='error'>Error parsing {os.path.basename(xml_file)}.</span><br/>"
            except Exception as e: summary += f"<span class='error'>Error processing {os.path.basename(xml_file)}: {e}</span><br/>"

        summary += f"<h4>Nmap Service Scan Summary ({len(all_open_ports)} hosts with open ports found across {total_hosts_scanned} hosts scanned):</h4><ul>"
        if all_open_ports:
             for host in sorted(all_open_ports.keys()):
                 port_details = "; ".join(f"{port_proto}: {service}" for port_proto, service in sorted(all_open_ports[host].items()))
                 summary += f"<li><b>{host}:</b> {port_details}</li>"
        else: summary += "<li>No open ports found in detailed scan.</li>"
        summary += "</ul>"
        return summary

    # --- HTML Structure ---
    html_parts = []
    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xeref Recon Report: {', '.join(report_data['targets'])}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; padding: 20px; max-width: 1200px; margin: auto; background-color: #f8f9fa; color: #343a40; }}
        h1, h2, h3 {{ color: #0056b3; border-bottom: 2px solid #dee2e6; padding-bottom: 8px; margin-top: 30px;}}
        h1 {{ text-align: center; margin-bottom: 30px; }}
        h4 {{ color: #495057; margin-bottom: 8px; font-weight: 600; }}
        .container {{ background-color: #ffffff; padding: 25px; border-radius: 8px; box-shadow: 0 2px 15px rgba(0,0,0,0.08); margin-bottom: 25px; border: 1px solid #e9ecef; }}
        ul {{ list-style-type: none; padding-left: 0; }}
        li {{ margin-bottom: 12px; padding-left: 20px; position: relative; }}
        li::before {{ content: '•'; color: #007bff; font-weight: bold; display: inline-block; width: 1em; margin-left: -1.5em; position: absolute; left: 10px;}}
        a {{ color: #007bff; text-decoration: none; font-weight: 500; }}
        a:hover {{ text-decoration: underline; color: #0056b3; }}
        code {{ background-color: #e9ecef; padding: 3px 6px; border-radius: 4px; font-family: 'Courier New', Courier, monospace; color: #c7254e; }}
        .file-link {{ margin-left: 15px; font-size: 0.9em; }}
        .summary-box {{ border: 1px solid #ced4da; padding: 20px; margin-top: 20px; border-radius: 6px; background-color: #f1f3f5; overflow-x: auto; }}
        .warning {{ color: #fd7e14; font-weight: bold; }} /* Orange */
        .error {{ color: #dc3545; font-weight: bold; }} /* Red */
        .success {{ color: #28a745; font-weight: bold; }} /* Green */
        .pending {{ color: #6c757d; font-style: italic; }} /* Gray */
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ border: 1px solid #dee2e6; padding: 8px 12px; text-align: left; }}
        th {{ background-color: #e9ecef; font-weight: 600; }}
        .details {{ margin-left: 20px; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>Xeref Reconnaissance Report</h1>
    <div class="container">
        <h2>Scan Overview</h2>
        <table>
            <tr><th>Target Domain(s)</th><td>{', '.join(report_data['targets'])}</td></tr>
            <tr><th>Input File</th><td>{report_data.get('input_file', 'N/A')}</td></tr>
            <tr><th>Scan Started</th><td>{report_data['start_time']}</td></tr>
            <tr><th>Report Generated</th><td>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
            <tr><th>Current Phase</th><td>{current_phase}</td></tr>
            <tr><th>Base Directory</th><td>{report_data['base_dir']}</td></tr>
            <tr><th>Max Workers (Threads)</th><td>{report_data.get('max_workers', 'N/A')}</td></tr>
        </table>
    </div>""")

    # --- Summary Section ---
    html_parts.append('<div class="container"><h2>Summary</h2><ul>')
    # Subdomain Summary
    sub_count = count_lines(report_data.get('consolidated_subs_file'))
    sub_link = create_link(report_data.get('consolidated_subs_file'), report_data['base_dir'])
    sub_summary = f"{sub_count} {sub_link}" if report_data.get('consolidated_subs_file') else "<span class='pending'>Pending...</span>"
    html_parts.append(f"<li><strong>Total Unique Subdomains Found:</strong> {sub_summary}</li>")
    # Httprobe Summary
    alive_count = count_lines(report_data.get('alive_hosts_file'))
    alive_link = create_link(report_data.get('alive_hosts_file'), report_data['base_dir'])
    alive_summary = f"{alive_count} {alive_link}" if report_data.get('alive_hosts_file') else "<span class='pending'>Pending...</span>"
    html_parts.append(f"<li><strong>Live Web Servers Found (HTTP/HTTPS):</strong> {alive_summary}</li>")
    # Takeover Summary
    takeover_results = report_data.get('takeover_results') # Check if key exists
    takeover_summary = f"<span class='warning'>{len(takeover_results)}</span> (See details below)" if isinstance(takeover_results, dict) and takeover_results else ("<span class='success'>0</span>" if takeover_results is not None else "<span class='pending'>Pending...</span>")
    html_parts.append(f"<li><strong>Potential Subdomain Takeovers Found:</strong> {takeover_summary}</li>")
    # Nuclei Summary
    web_scan_results_summary = report_data.get('web_scan_results') # Get dict or None
    nuclei_report_path = web_scan_results_summary.get('nuclei_report') if isinstance(web_scan_results_summary, dict) else None
    nuclei_summary = f"<span class='warning'>{count_lines(nuclei_report_path)}</span> {create_link(nuclei_report_path, report_data['base_dir'])}" if nuclei_report_path else ("<span class='success'>0</span>" if web_scan_results_summary is not None else "<span class='pending'>Pending...</span>")
    html_parts.append(f"<li><strong>Nuclei Findings (General Web Scan):</strong> {nuclei_summary}</li>")
    # Nikto Summary
    nikto_report_path = web_scan_results_summary.get('nikto_report') if isinstance(web_scan_results_summary, dict) else None
    nikto_summary = f"<span class='warning'>{count_lines(nikto_report_path)}</span> {create_link(nikto_report_path, report_data['base_dir'])}" if nikto_report_path else ("<span class='success'>0</span>" if web_scan_results_summary is not None else "<span class='pending'>Pending...</span>")
    html_parts.append(f"<li><strong>Nikto Findings:</strong> {nikto_summary}</li>")
    # CMS Summary
    cms_results = report_data.get('cms_scan_results')
    cms_details = cms_results.get('cms_scan_details', {}) if isinstance(cms_results, dict) else {}
    cms_output_dir = cms_results.get('cms_scan_output_dir') if isinstance(cms_results, dict) else None
    cms_summary = f"<span class='warning'>{len(cms_details)} Hosts with Findings</span> {create_link(cms_output_dir, report_data['base_dir'])}" if cms_details else ("<span class='success'>0</span>" if cms_results is not None and cms_results != "Skipped" else ("<span class='pending'>Pending...</span>" if cms_results is None else "Skipped"))
    html_parts.append(f"<li><strong>CMS Scan Findings:</strong> {cms_summary}</li>")
    # S3 Summary
    s3_results = report_data.get('s3_check_results')
    s3_details = s3_results.get('s3_check_details', {}) if isinstance(s3_results, dict) else {}
    s3_output_dir = s3_results.get('s3_check_output_dir') if isinstance(s3_results, dict) else None
    s3_summary = f"<span class='warning'>{len(s3_details)} Buckets with Findings</span> {create_link(s3_output_dir, report_data['base_dir'])}" if s3_details else ("<span class='success'>0</span>" if s3_results is not None and s3_results != "Skipped" else ("<span class='pending'>Pending...</span>" if s3_results is None else "Skipped"))
    html_parts.append(f"<li><strong>Potential S3 Bucket Findings:</strong> {s3_summary}</li>")
    # Secrets Summary
    secrets_results = report_data.get('secrets_scan_results')
    secrets_summary = f"<span class='warning'>{len(secrets_results)}</span> (See details below)" if isinstance(secrets_results, dict) and secrets_results else ("<span class='success'>0</span>" if secrets_results is not None and secrets_results != "Skipped" and secrets_results != "Not Configured" else ("<span class='pending'>Pending...</span>" if secrets_results is None else secrets_results)) # Handle None, Skipped, Not Configured
    html_parts.append(f"<li><strong>Potential Secrets Found (Local Scan):</strong> {secrets_summary}</li>")
    html_parts.append('</ul></div>')

    # --- Subdomain Enumeration Section ---
    html_parts.append('<div class="container"><h2>Subdomain Enumeration (Per Target)</h2>')
    if report_data.get('per_target_results'):
        html_parts.append("<ul>")
        for target in report_data['targets']:
            target_sub_file = report_data['per_target_results'].get(target, {}).get('subdomains_file')
            html_parts.append(f"<li><strong>{target}:</strong> {count_lines(target_sub_file)} unique subdomains found {create_link(target_sub_file, report_data['base_dir'])}</li>")
        html_parts.append('</ul>')
        html_parts.append(f"<p>Consolidated List: {create_link(report_data.get('consolidated_subs_file'), report_data['base_dir'])}</p>")
    else:
         html_parts.append("<p class='pending'>Pending...</p>")
    html_parts.append('</div>')

    # --- Port Scan Section ---
    html_parts.append('<div class="container"><h2>Port Scanning (Masscan + Nmap) & Live Hosts (Httprobe)</h2>')
    html_parts.append(f"<p>Live Hosts File: {create_link(report_data.get('alive_hosts_file'), report_data['base_dir'])}</p>")
    port_scan_results = report_data.get('port_scan_results')
    if port_scan_results == "Skipped":
         html_parts.append("<p>Port scans skipped.</p>")
    elif port_scan_results == "No IPs Resolved":
         html_parts.append("<p>Port scans skipped (no IPs resolved).</p>")
    elif isinstance(port_scan_results, dict):
        ps_res = port_scan_results
        html_parts.append(f"<h4>Masscan Results:</h4><ul><li>JSON Output: {create_link(ps_res.get('masscan_output'), report_data['base_dir'])}</li></ul>")
        html_parts.append("<h4>Nmap Results:</h4>")
        nmap_results_dir = ps_res.get('nmap_results_dir')
        if nmap_results_dir:
            html_parts.append(f"<p>Individual Host Results Directory: {create_link(nmap_results_dir, report_data['base_dir'])}</p>")
            # Use the directory path for summary parsing
            html_parts.append(f"<div class='summary-box'>{parse_nmap_xml_summary(nmap_results_dir)}</div>")
        else:
             html_parts.append("<p>Nmap scans did not produce results.</p>")
    else: # Pending
        html_parts.append("<p class='pending'>Port scans pending...</p>")
    html_parts.append('</div>')

    # --- Takeover Section ---
    html_parts.append('<div class="container"><h2>Subdomain Takeover Check</h2>')
    takeover_results = report_data.get('takeover_results')
    if takeover_results is not None: # Check if scan has run
        if isinstance(takeover_results, dict) and takeover_results:
            html_parts.append("<p class='warning'>Potential Takeovers Found (Manual Verification Required):</p><ul>")
            for tool in sorted(takeover_results.keys()):
                file_path = takeover_results[tool]
                html_parts.append(f"<li><strong>{tool.replace('_', ' ').title()}:</strong> {create_link(file_path, report_data['base_dir'])} ({count_lines(file_path)} findings)</li>")
            html_parts.append("</ul>")
        else:
            html_parts.append("<p class='success'>No potential subdomain takeovers found.</p>")
    else:
         html_parts.append("<p class='pending'>Pending...</p>")
    html_parts.append('</div>')

    # --- Web Analysis Section ---
    html_parts.append('<div class="container"><h2>Web Server Analysis (on Live Hosts)</h2>')
    wsr = report_data.get('web_scan_results')
    if wsr is not None:
        if isinstance(wsr, dict) and wsr:
            html_parts.append("<ul>")
            html_parts.append(f"<li><strong>Eyewitness Screenshots:</strong> {create_link(wsr.get('eyewitness_report'), report_data['base_dir'])}</li>")
            html_parts.append(f"<li><strong>Nuclei Scan Report (General):</strong> {count_lines(wsr.get('nuclei_report'))} findings {create_link(wsr.get('nuclei_report'), report_data['base_dir'])}</li>")
            html_parts.append(f"<li><strong>Nikto Scan Report:</strong> {count_lines(wsr.get('nikto_report'))} findings {create_link(wsr.get('nikto_report'), report_data['base_dir'])}</li>")
            html_parts.append(f"<li><strong>GoSpider Output Directory:</strong> {create_link(wsr.get('gospider_output_dir'), report_data['base_dir'])}</li>")
            html_parts.append(f"<li><strong>Wayback URLs:</strong> {count_lines(wsr.get('wayback_urls'))} URLs {create_link(wsr.get('wayback_urls'), report_data['base_dir'])}</li>")
            html_parts.append(f"<li><strong>Wayback Params:</strong> {count_lines(wsr.get('wayback_params'))} params {create_link(wsr.get('wayback_params'), report_data['base_dir'])}</li>")
            html_parts.append(f"<li><strong>Wayback Extensions:</strong> {count_lines(wsr.get('wayback_extensions'))} extensions {create_link(wsr.get('wayback_extensions'), report_data['base_dir'])}</li>")
            html_parts.append("</ul>")
        else:
            html_parts.append("<p>Web server analysis scans run, but found no results.</p>")
    else:
        html_parts.append("<p class='pending'>Pending...</p>")
    html_parts.append('</div>')

    # --- CMS Section ---
    html_parts.append('<div class="container"><h2>CMS Scanning (WordPress Focused)</h2>')
    cms_results = report_data.get('cms_scan_results')
    if cms_results == "Skipped":
        html_parts.append("<p>CMS scans were skipped.</p>")
    elif isinstance(cms_results, dict):
        cms_details = cms_results.get('cms_scan_details', {})
        cms_output_dir = cms_results.get('cms_scan_output_dir')
        if cms_details:
            html_parts.append(f"<p>Scan results directory: {create_link(cms_output_dir, report_data['base_dir'])}</p>")
            html_parts.append("<p>Hosts with findings:</p><ul>")
            for host, findings in sorted(cms_details.items()):
                html_parts.append(f"<li><strong>{host}:</strong>")
                html_parts.append("<ul class='details'>")
                for tool, file_path in findings.items():
                     html_parts.append(f"<li>{tool.title()}: {create_link(file_path, report_data['base_dir'])}</li>")
                html_parts.append("</ul></li>")
            html_parts.append("</ul>")
        else: # Scan was run but no findings
             html_parts.append("<p>CMS scans run, but no findings reported.</p>")
    else: # Pending
         html_parts.append("<p class='pending'>Pending...</p>")
    html_parts.append('</div>')

    # --- JS/GAU Section ---
    html_parts.append('<div class="container"><h2>JavaScript & URL Discovery (GAU)</h2>')
    jgr = report_data.get('js_gau_results')
    if jgr is not None:
        if isinstance(jgr, dict) and jgr:
            html_parts.append(f"<p>Combined potential links/endpoints found: {count_lines(jgr.get('js_gau_links'))} {create_link(jgr.get('js_gau_links'), report_data['base_dir'])}</p>")
        else:
            html_parts.append("<p>JS/GAU scans run, but found no results.</p>")
    else:
        html_parts.append("<p class='pending'>Pending...</p>")
    html_parts.append('</div>')

    # --- Tech Fingerprint Section ---
    html_parts.append('<div class="container"><h2>Technology Fingerprinting</h2>')
    tfr = report_data.get('tech_fingerprint_results')
    if tfr is not None:
        if isinstance(tfr, dict) and tfr:
             html_parts.append("<ul>")
             html_parts.append(f"<li><strong>Wappalyzer Results (JSONL):</strong> {create_link(tfr.get('wappalyzer_report'), report_data['base_dir'])}</li>")
             html_parts.append(f"<li><strong>Webanalyze Results (JSON):</strong> {create_link(tfr.get('webanalyze_report'), report_data['base_dir'])}</li>")
             html_parts.append("</ul>")
        else:
             html_parts.append("<p>Technology fingerprinting scans run, but found no results.</p>")
    else:
        html_parts.append("<p class='pending'>Pending...</p>")
    html_parts.append('</div>')

    # --- Misc Scans Section ---
    html_parts.append('<div class="container"><h2>Miscellaneous Scans</h2>')
    msr = report_data.get('misc_scan_results')
    if msr is not None:
        if isinstance(msr, dict) and msr:
             html_parts.append("<ul>")
             if msr.get('dirsearch_reports_dir'):
                 html_parts.append(f"<li><strong>Dirsearch Reports:</strong> Directory {create_link(msr.get('dirsearch_reports_dir'), report_data['base_dir'])}</li>")
             if msr.get('corsy_report'):
                 html_parts.append(f"<li><strong>Corsy Report:</strong> {count_lines(msr.get('corsy_report'))} findings {create_link(msr.get('corsy_report'), report_data['base_dir'])}</li>")
             if msr.get('sniper_report'):
                 html_parts.append(f"<li><strong>Sniper Report (DNS Focus):</strong> {count_lines(msr.get('sniper_report'))} lines {create_link(msr.get('sniper_report'), report_data['base_dir'])}</li>")
             html_parts.append("</ul>")
        else:
             html_parts.append("<p>Miscellaneous scans run, but found no results.</p>")
    else:
        html_parts.append("<p class='pending'>Pending...</p>")
    html_parts.append('</div>')

    # --- S3 Bucket Section ---
    html_parts.append('<div class="container"><h2>S3 Bucket Checks (Derived Names)</h2>')
    s3r = report_data.get('s3_check_results')
    if s3r == "Skipped":
        html_parts.append("<p>S3 bucket checks were skipped.</p>")
    elif isinstance(s3r, dict):
        s3_details = s3r.get('s3_check_details', {})
        s3_output_dir = s3r.get('s3_check_output_dir')
        if s3_details:
            html_parts.append(f"<p>Scan results directory: {create_link(s3_output_dir, report_data['base_dir'])}</p>")
            html_parts.append("<p class='warning'>Potential Findings (Manual Verification Required):</p><ul>")
            for bucket, findings in sorted(s3_details.items()):
                html_parts.append(f"<li><strong>{bucket}:</strong>")
                html_parts.append("<ul class='details'>")
                for tool, file_path in findings.items():
                     html_parts.append(f"<li>{tool}: {create_link(file_path, report_data['base_dir'])}</li>")
                html_parts.append("</ul></li>")
            html_parts.append("</ul>")
        else: # Scan run but no findings
            html_parts.append("<p>S3 bucket checks run, but no findings reported.</p>")
    else: # Pending
         html_parts.append("<p class='pending'>Pending...</p>")
    html_parts.append('</div>')

    # --- Secrets Section ---
    html_parts.append('<div class="container"><h2>Secrets Scanning</h2>')
    html_parts.append('<p class="warning">Note: These scans target local file paths specified via -s/--secrets.</p>')
    ssr = report_data.get('secrets_scan_results')
    secrets_target = report_data.get('secrets_scan_target')
    if ssr == "Skipped":
        html_parts.append("<p>Secrets scans were skipped.</p>")
    elif ssr == "Not Configured":
         html_parts.append("<p>Secrets scans were not configured (no -s path provided).</p>")
    elif isinstance(ssr, dict):
        if ssr:
             html_parts.append("<p class='warning'>Potential Secrets Found (Manual Verification Required):</p><ul>")
             for tool in sorted(ssr.keys()):
                 file_path = ssr[tool]
                 html_parts.append(f"<li><strong>{tool.replace('_', ' ').title()}:</strong> {create_link(file_path, report_data['base_dir'])}</li>")
             html_parts.append("</ul>")
        else:
             html_parts.append("<p class='success'>No secrets found by configured tools.</p>")
    elif secrets_target: # Check if target was specified but scan is pending/failed
         html_parts.append(f"<p>Secrets scans run on '{secrets_target}' but found no results or are pending.</p>")
    else: # Not configured or Pending
         html_parts.append("<p class='pending'>Pending...</p>")
    html_parts.append('</div>')

    # --- Footer ---
    html_parts.append("</body></html>")

    # --- Write Report ---
    final_html = "".join(html_parts)
    try:
        # Use a lock to prevent race conditions if multiple threads somehow call this
        with print_lock: # Re-using print_lock for file writing safety
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(final_html)
        # safe_print(f"[+] HTML report updated: {report_file}") # Reduce noise
    except Exception as e:
        safe_print(f"[!] Error writing HTML report {report_file}: {e}", file=sys.stderr)



# --- Main Execution ---

# Define phases and their dependencies & associated tools/actions
PHASES = {
    "subdomain_enum": {"deps": [], "desc": "Subdomain discovery (Amass, Subfinder, Sublist3r, OneForAll, Assetnote, Knockpy, Sudomy, bbot, Censys, Assetfinder, crtsh, SecurityTrails)"},
    "dns_resolve": {"deps": ["subdomain_enum"], "desc": "Resolve subdomains to IPs (dnsx/socket)"},
    "httprobe": {"deps": ["subdomain_enum"], "desc": "Check for live web servers (httprobe)"},
    "port_scan": {"deps": ["dns_resolve"], "desc": "Port scanning (Masscan + Nmap -sCV)"},
    "takeover": {"deps": ["subdomain_enum"], "desc": "Subdomain takeover checks (Subjack, Nuclei)"},
    "web_scan": {"deps": ["httprobe"], "desc": "Web analysis (Eyewitness, Nuclei-general, Nikto, GoSpider, Waybackurls)"},
    "cms_scan": {"deps": ["httprobe"], "desc": "CMS scanning (WPScan)"},
    "js_gau": {"deps": ["httprobe"], "desc": "JavaScript/URL discovery (JS-Scanner, GAU)"},
    "tech_fp": {"deps": ["httprobe"], "desc": "Technology fingerprinting (Wappalyzer, Webanalyze)"},
    "misc_scan": {"deps": ["httprobe", "subdomain_enum"], "desc": "Miscellaneous scans (Dirsearch, Corsy, Sniper)"},
    "s3_check": {"deps": ["subdomain_enum"], "desc": "S3 bucket checks (S3Scanner, AWSBucketDump)"},
    "secrets": {"deps": [], "desc": "Local secrets scanning (Git-Secrets, Gitleaks, TruffleHog)"},
}

def main():
    start_time = time.time()
    start_time_str = datetime.datetime.now().strftime('%Y-%m-%d_%H%M%S')

    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(
        description="Xeref - Automated Reconnaissance Scanner", # Renamed Tool
        formatter_class=argparse.RawTextHelpFormatter # Use RawTextHelpFormatter for better help text formatting
    )
    parser.add_argument('targets', nargs='*', help="Target domain(s) separated by space.")
    parser.add_argument('-f', '--file', help="File containing target domains (one per line).")
    parser.add_argument('-s', '--secrets', metavar='/path/to/scan', help="Local directory for secrets scanning.")
    parser.add_argument('-w', '--workers', type=int, default=DEFAULT_MAX_WORKERS, help="Number of parallel workers (threads).")
    parser.add_argument('--skip-install', action='store_true', help="Skip tool check and installation attempt.")
    parser.add_argument('--install-tools', action='store_true', help="Attempt to install missing tools without prompting.")

    # Add skip flags for each phase with detailed help
    skip_group = parser.add_argument_group('Skip specific phases')
    for phase, details in PHASES.items():
        skip_group.add_argument(
            f'--skip-{phase.replace("_", "-")}',
            action='store_true',
            help=f"Skip the {phase} phase.\n    Description: {details['desc']}"
        )

    # Add only-run flag with detailed help
    parser.add_argument(
        '--only-run',
        metavar='PHASES',
        help=f"Only run the specified phases (comma-separated) and their dependencies.\nAvailable phases:\n" + \
             "\n".join([f"  - {p}: {d['desc']}" for p, d in PHASES.items()])
    )

    args = parser.parse_args()

    # --- Tool Installation Check ---
    if not args.skip_install:
        install_successful = check_and_install_tools(force_install=args.install_tools, skip_install=args.skip_install)
        if not (args.targets or args.file):
             safe_print("[*] Tool check/installation finished. No targets specified, exiting.")
             sys.exit(0)
        elif not install_successful:
             safe_print("[!] Proceeding with scan despite missing optional tools.")
    elif not (args.targets or args.file):
        # Allow running only --install-tools without targets
        if args.install_tools:
             check_and_install_tools(force_install=True, skip_install=False)
             safe_print("[*] Tool installation finished. No targets specified, exiting.")
             sys.exit(0)
        else:
             safe_print("[*] Tool installation skipped and no targets provided. Exiting.")
             sys.exit(0)


    # --- Process Targets ---
    targets = args.targets
    input_file = args.file
    if input_file:
        safe_print(f"[*] Reading targets from file: {input_file}")
        try: targets.extend(read_file_lines(input_file))
        except Exception as e: safe_print(f"[!] Error reading targets file {input_file}: {e}", file=sys.stderr); sys.exit(1)
    targets = sorted(list(set(filter(None, [t.strip() for t in targets]))))
    # Check if targets exist *after* potentially loading from file
    if not targets:
        safe_print("[!] No target domains provided either via arguments or file.", file=sys.stderr)
        parser.print_help(); sys.exit(1)


    # --- Process Options ---
    secrets_scan_target_path = args.secrets
    max_workers = args.workers if args.workers > 0 else DEFAULT_MAX_WORKERS

    # --- Determine Phases to Run/Skip ---
    phases_to_run = set(PHASES.keys()) # Default: run all
    phases_to_skip = set()
    skipped_due_to_dependency = set()

    # Process --only-run
    if args.only_run:
        requested_phases = set(p.strip() for p in args.only_run.split(',') if p.strip())
        valid_requested = requested_phases.intersection(PHASES.keys())
        invalid_requested = requested_phases.difference(PHASES.keys())
        if invalid_requested:
            safe_print(f"[!] Invalid phase names in --only-run: {', '.join(invalid_requested)}", file=sys.stderr)
        phases_to_run = set()
        # Add requested phases and their dependencies recursively
        phases_to_add = set(valid_requested)
        while phases_to_add:
            phase = phases_to_add.pop()
            if phase not in phases_to_run:
                phases_to_run.add(phase)
                # Add dependencies of this phase to the set to be processed
                phases_to_add.update(PHASES.get(phase, {}).get('deps', []))
        safe_print(f"[*] --only-run specified. Effective phases to run (including dependencies): {', '.join(sorted(list(phases_to_run)))}")

    # Process --skip-<phase> flags
    for phase in PHASES:
        skip_flag_name = f'skip_{phase.replace("-", "_")}' # Ensure flag name matches attribute name
        if getattr(args, skip_flag_name, False):
            phases_to_skip.add(phase)

    safe_print(f"[*] Starting Xeref recon scan for targets: {', '.join(targets)}") # Renamed Tool
    safe_print(f"[*] Using max {max_workers} parallel workers.")
    if secrets_scan_target_path: safe_print(f"[*] Secrets scan target directory specified: {secrets_scan_target_path}")
    if phases_to_skip: safe_print(f"[*] Explicitly skipping phases: {', '.join(sorted(list(phases_to_skip)))}")


    # --- Setup Results Directories ---
    overall_base_dir = f"xeref_results_{start_time_str}" # Renamed Tool Output Dir
    make_dir(overall_base_dir)
    combined_results_dir = os.path.join(overall_base_dir, "_combined_results")
    make_dir(combined_results_dir)
    report_file = os.path.join(overall_base_dir, "xeref_report.html") # Renamed Tool Report File

    # --- Initialize Report Data ---
    report_data = {
        "targets": targets, "input_file": input_file, "start_time": start_time_str,
        "base_dir": os.path.abspath(overall_base_dir), "max_workers": max_workers,
        "per_target_results": {}, "port_scan_results": None, "takeover_results": None,
        "web_scan_results": None, "cms_scan_results": None, "js_gau_results": None,
        "tech_fingerprint_results": None, "misc_scan_results": None, "s3_check_results": None,
        "secrets_scan_results": None, "secrets_scan_target": secrets_scan_target_path,
        "ip_to_domain_map": {}
    }
    # Pre-mark phases as skipped based on args
    for phase in PHASES:
        if phase not in phases_to_run or phase in phases_to_skip:
             report_data[f"{phase}_results"] = "Skipped" # Use the key format consistently

    # --- Generate Initial HTML Report ---
    generate_html_report(report_file, report_data, current_phase="Initializing")

    # --- Main Workflow with ThreadPoolExecutor ---
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:

        # Function to check if a phase should run
        def should_run(phase_name):
            if phase_name not in phases_to_run: return False
            if phase_name in phases_to_skip: return False
            # Check dependencies
            for dep in PHASES.get(phase_name, {}).get('deps', []):
                if dep in phases_to_skip or dep in skipped_due_to_dependency:
                    safe_print(f"[*] Skipping phase '{phase_name}' because dependency '{dep}' was skipped.")
                    skipped_due_to_dependency.add(phase_name)
                    report_data[f"{phase_name}_results"] = f"Skipped (Dependency {dep} Skipped)"
                    return False
            return True

        # --- Phase 1: Subdomain Enumeration ---
        consolidated_subs_file = None # Initialize
        if should_run("subdomain_enum"):
            current_phase = "Subdomain Enumeration"
            safe_print(f"[*] Starting Phase: {current_phase}")
            enum_futures = {}
            for target in targets:
                target_recon_base = os.path.join(overall_base_dir, target, "recon")
                make_dir(target_recon_base)
                report_data["per_target_results"][target] = {}
                future = executor.submit(enum_subdomains, target, target_recon_base, executor)
                enum_futures[future] = target
            all_target_subdomain_files = []
            for future in concurrent.futures.as_completed(enum_futures):
                target = enum_futures[future]
                try:
                    target_subs_file = future.result()
                    if target_subs_file and os.path.exists(target_subs_file):
                        all_target_subdomain_files.append(target_subs_file)
                        report_data["per_target_results"][target]['subdomains_file'] = os.path.abspath(target_subs_file)
                except Exception as e: safe_print(f"[!] Error during subdomain enumeration for {target}: {e}", file=sys.stderr)

            # Consolidate immediately after enumeration finishes
            current_phase_consolidation = "Subdomain Consolidation"
            safe_print(f"[*] Starting Phase: {current_phase_consolidation}")
            consolidated_subs = set()
            for subs_file in all_target_subdomain_files: consolidated_subs.update(read_file_lines(subs_file))
            if not consolidated_subs:
                 safe_print("[!] No subdomains found. Exiting."); generate_html_report(report_file, report_data, current_phase="No Subdomains Found")
                 sys.exit(0)
            consolidated_subs_list = sorted(list(consolidated_subs))
            consolidated_subs_file = os.path.join(combined_results_dir, "all_subdomains.txt")
            write_lines_to_file(consolidated_subs_file, consolidated_subs_list)
            report_data['consolidated_subs_file'] = os.path.abspath(consolidated_subs_file)
            safe_print(f"[*] Consolidated {len(consolidated_subs_list)} unique subdomains.")
            generate_html_report(report_file, report_data, current_phase=f"{current_phase_consolidation} Complete")
        else:
             safe_print("[*] Skipping Subdomain Enumeration phase.")
             generate_html_report(report_file, report_data, current_phase="Subdomain Enumeration Skipped")
             safe_print("[!] Cannot proceed without subdomain enumeration results. Exiting.")
             sys.exit(1)


        # --- Phase 2: Resolve IPs ---
        ips_file = None
        ip_domain_map = {}
        if should_run("dns_resolve"):
            current_phase = "DNS Resolution"
            safe_print(f"[*] Starting Phase: {current_phase}")
            ips_file, ip_domain_map = resolve_domains_to_ips(consolidated_subs_file, combined_results_dir)
            report_data['ip_to_domain_map'] = ip_domain_map
            generate_html_report(report_file, report_data, current_phase=f"{current_phase} Complete")
        else:
            safe_print("[*] Skipping DNS Resolution phase.")
            # skipped_due_to_dependency.add("dns_resolve") # Already marked by should_run
            generate_html_report(report_file, report_data, current_phase="DNS Resolution Skipped")


        # --- Phase 3: Parallel Port Scans (using IPs) & Httprobe (using Domains) ---
        current_phase = "Port Scanning & Live Host Discovery"
        safe_print(f"[*] Starting Phase: {current_phase}")
        portscan_output_dir = os.path.join(combined_results_dir, "port_scans")
        alive_hosts_file_path = os.path.join(combined_results_dir, "alive_hosts_httprobe.txt")
        portscan_future = None
        httprobe_future = None

        if should_run("port_scan"):
            if ips_file: # Only run portscan if we have IPs
                portscan_future = executor.submit(run_port_scans_parallel, ips_file, portscan_output_dir, executor, report_data['ip_to_domain_map'])
            else:
                 safe_print("[!] Skipping Port Scanning as no IPs were resolved.")
                 report_data['port_scan_results'] = "Skipped (No IPs)"
                 skipped_due_to_dependency.add("port_scan")
        # else: report_data['port_scan_results'] = "Skipped" # Already marked

        if should_run("httprobe"):
            httprobe_future = executor.submit(run_httprobe, consolidated_subs_file, alive_hosts_file_path)
        # else: report_data["httprobe_results"] = "Skipped" # Already marked


        # --- Phase 4: Wait for Httprobe, check results ---
        alive_hosts_file = None
        if httprobe_future: # Only wait if it was submitted
            safe_print("[*] Waiting for Httprobe to complete...")
            try:
                alive_hosts_file = httprobe_future.result()
                if not alive_hosts_file or not os.path.exists(alive_hosts_file) or os.path.getsize(alive_hosts_file) == 0:
                     raise ValueError("Httprobe failed or found no live hosts.")
                report_data['alive_hosts_file'] = os.path.abspath(alive_hosts_file)
                safe_print("[+] Httprobe completed.")
                generate_html_report(report_file, report_data, current_phase="Live Host Discovery Complete")
            except Exception as e:
                safe_print(f"[!] {e}. Cannot proceed with web-dependent scans.", file=sys.stderr)
                # Mark dependent phases as skipped
                for phase, details in PHASES.items():
                    if "httprobe" in details.get('deps', []): skipped_due_to_dependency.add(phase)
                alive_hosts_file = None # Ensure it's None so subsequent scans are skipped
                generate_html_report(report_file, report_data, current_phase="Httprobe Failed")
                # Don't exit here, let portscan finish if running
        elif "httprobe" in skipped_due_to_dependency:
             # Mark dependent phases as skipped
             for phase, details in PHASES.items():
                 if "httprobe" in details.get('deps', []): skipped_due_to_dependency.add(phase)
             generate_html_report(report_file, report_data, current_phase="Live Host Discovery Skipped")


        # --- Phase 5: Submit All Remaining Parallel Scans ---
        current_phase = "Vulnerability & Info Gathering Scans"
        safe_print(f"[*] Starting Phase: {current_phase}")
        takeover_output_dir = os.path.join(combined_results_dir, "potential_takeovers")
        web_scans_output_dir = os.path.join(combined_results_dir, "web_scans")
        cms_scans_output_dir = os.path.join(combined_results_dir, "cms_scans")
        js_gau_output_dir = os.path.join(combined_results_dir, "js_gau")
        tech_fp_output_dir = os.path.join(combined_results_dir, "fingerprints")
        misc_scans_output_dir = os.path.join(combined_results_dir, "misc_scans")
        s3_checks_output_dir = os.path.join(combined_results_dir, "s3_checks")
        for d in [takeover_output_dir, web_scans_output_dir, cms_scans_output_dir, js_gau_output_dir, tech_fp_output_dir, misc_scans_output_dir, s3_checks_output_dir]: make_dir(d)

        # Store futures in a dictionary to track completion
        scan_futures = {}
        if portscan_future: scan_futures["port_scan"] = portscan_future # Add portscan future if it exists

        # Submit other scans only if their dependencies are met
        if should_run("takeover"): scan_futures["takeover"] = executor.submit(run_subdomain_takeover_parallel, consolidated_subs_file, takeover_output_dir, executor)
        if should_run("web_scan"): scan_futures["web_scan"] = executor.submit(run_web_scans_parallel, alive_hosts_file, web_scans_output_dir, executor)
        if should_run("cms_scan"): scan_futures["cms_scan"] = executor.submit(run_cms_scans_parallel, alive_hosts_file, cms_scans_output_dir, executor)
        if should_run("js_gau"): scan_futures["js_gau"] = executor.submit(run_js_and_gau_parallel, alive_hosts_file, js_gau_output_dir, executor)
        if should_run("tech_fp"): scan_futures["tech_fp"] = executor.submit(run_tech_fingerprint_parallel, alive_hosts_file, tech_fp_output_dir, executor)
        if should_run("misc_scan"): scan_futures["misc_scan"] = executor.submit(run_misc_tools_parallel, alive_hosts_file, consolidated_subs_file, misc_scans_output_dir, executor)
        if should_run("s3_check"): scan_futures["s3_check"] = executor.submit(run_s3_bucket_checks_parallel, consolidated_subs_file, s3_checks_output_dir, executor)


        # --- Phase 6: Collect All Results & Update Report Incrementally ---
        safe_print("[*] Waiting for scans to complete and updating report...")
        completed_tasks = 0
        total_tasks = len(scan_futures)

        for future in concurrent.futures.as_completed(scan_futures.values()):
             task_name = None
             for name, f in scan_futures.items():
                 if f == future: task_name = name; break
             if not task_name: continue

             try:
                 result = future.result(); safe_print(f"[+] Task '{task_name}' completed ({completed_tasks + 1}/{total_tasks}).") # Increment here for logging
                 # Store results based on task name (using absolute paths)
                 if task_name == "port_scan": report_data['port_scan_results'] = result # Result is already a dict
                 elif task_name == "takeover": report_data['takeover_results'] = {k: os.path.abspath(v) for k, v in result.items()} if isinstance(result, dict) else {}
                 elif task_name == "web_scan": report_data['web_scan_results'] = {k: os.path.abspath(v) for k, v in result.items()} if isinstance(result, dict) else {}
                 elif task_name == "js_gau": report_data['js_gau_results'] = {k: os.path.abspath(v) for k, v in result.items()} if isinstance(result, dict) else {}
                 elif task_name == "tech_fp": report_data['tech_fingerprint_results'] = {k: os.path.abspath(v) for k, v in result.items()} if isinstance(result, dict) else {}
                 elif task_name == "misc_scan": report_data['misc_scan_results'] = {k: os.path.abspath(v) for k, v in result.items()} if isinstance(result, dict) else {}
                 elif task_name == "cms_scan":
                     if isinstance(result, dict): # Ensure result is a dict before processing
                         if 'cms_scan_details' in result:
                             for host, findings in result['cms_scan_details'].items(): result['cms_scan_details'][host] = {k: os.path.abspath(v) for k, v in findings.items()}
                         if 'cms_scan_output_dir' in result: result['cms_scan_output_dir'] = os.path.abspath(result['cms_scan_output_dir'])
                         report_data['cms_scan_results'] = result
                     else: report_data['cms_scan_results'] = {} # Handle case where function returns non-dict on error/skip
                 elif task_name == "s3_check":
                     if isinstance(result, dict): # Ensure result is a dict
                         if 's3_check_details' in result:
                             for bucket, findings in result['s3_check_details'].items(): result['s3_check_details'][bucket] = {k: os.path.abspath(v) for k, v in findings.items()}
                         if 's3_check_output_dir' in result: result['s3_check_output_dir'] = os.path.abspath(result['s3_check_output_dir'])
                         report_data['s3_check_results'] = result
                     else: report_data['s3_check_results'] = {}

                 completed_tasks += 1 # Increment after successful processing
                 # Update HTML report after each task completes
                 generate_html_report(report_file, report_data, current_phase=f"{current_phase} ({completed_tasks}/{total_tasks} Complete)")

             except Exception as e:
                 completed_tasks += 1 # Count it as completed even if it failed
                 safe_print(f"[!] Error collecting results for task '{task_name}': {e}", file=sys.stderr)
                 # Update report indicating error for this task if needed
                 report_data[f"{task_name}_results"] = f"Error: {e}" # Store error message
                 generate_html_report(report_file, report_data, current_phase=f"{current_phase} ({completed_tasks}/{total_tasks} Complete - Error in {task_name})")


        # Phase 7: Secrets Scanning (Sequential)
        current_phase = "Secrets Scanning"
        if should_run("secrets"):
            safe_print(f"[*] Starting Phase: {current_phase}")
            if secrets_scan_target_path:
                secrets_output_dir = os.path.join(overall_base_dir, "_secrets_scan")
                secrets_results = run_secrets_scans(secrets_scan_target_path, secrets_output_dir)
                report_data['secrets_scan_results'] = {k: os.path.abspath(v) for k, v in secrets_results.items()} if isinstance(secrets_results, dict) else {}
            else:
                safe_print("[*] Skipping secrets scanning as no target path was provided.")
                report_data['secrets_scan_results'] = "Not Configured" # Mark as not configured
        # else: report_data['secrets_scan_results'] = "Skipped" # Already marked if skipped
        generate_html_report(report_file, report_data, current_phase="Scan Complete")


    # Phase 8: Final Report Generation (already updated incrementally)
    safe_print("[*] All scans finished.")

    end_time = time.time()
    safe_print(f"\n[+] Reconnaissance complete for: {', '.join(targets)}")
    safe_print(f"[+] All results saved in directory: {os.path.abspath(overall_base_dir)}")
    safe_print(f"[+] HTML report: {os.path.abspath(report_file)}")
    safe_print(f"[+] Total execution time: {end_time - start_time:.2f} seconds.")


if __name__ == "__main__":
    main()
  
