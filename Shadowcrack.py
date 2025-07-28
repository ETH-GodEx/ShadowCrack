# shadowcrack.py
# Author: GodEx

import hashlib
import pyfiglet
from termcolor import colored
import os
import sys
import time
import shutil

try:
    from prompt_toolkit import prompt
    from prompt_toolkit.completion import PathCompleter
    USE_PROMPT_TOOLKIT = True
except ImportError:
    USE_PROMPT_TOOLKIT = False

# ------------------- Dependency Check ------------------- #
def check_dependencies():
    import importlib.util
    required = ["pyfiglet", "termcolor"]
    missing = []
    for pkg in required:
        if importlib.util.find_spec(pkg) is None:
            missing.append(pkg)

    if missing:
        print(colored(f"[!] Missing dependencies: {', '.join(missing)}", "red"))
        print(colored("[*] Installing dependencies...", "yellow"))
        os.system(f"pip install {' '.join(missing)}")
        print(colored("[✓] Dependencies installed. Please re-run the tool.", "green"))
        sys.exit(0)

# ------------------- ASCII Banner ------------------- #
def print_banner():
    banner = pyfiglet.figlet_format("ShadowCrack", font="slant")
    print(colored(banner, "red"))
    print(colored("🔓 The Stealthy Password Cracker & Generator", "white"))
    print(colored("📜 Supports: MD5 | SHA1 | SHA256 | SHA512 | NTLM | SHA3 | etc.", "yellow"))
    print(colored("💻 Author: ETH-GodEx", "green"))
    print("-" * 60 + "\n")

# ------------------- Hash Functions ------------------- #
def get_hash_function(algorithm):
    algorithm = algorithm.lower()
    if algorithm == 'ntlm':
        return lambda x: hashlib.new('md4', x.encode('utf-16le')).hexdigest()
    try:
        return lambda x: getattr(hashlib, algorithm)(x.encode()).hexdigest()
    except AttributeError:
        raise ValueError("Unsupported algorithm.")

# ------------------- Identify Hash Type ------------------- #
def identify_hash_type(hash_str):
    length = len(hash_str)
    return {
        32: 'md5',
        40: 'sha1',
        56: 'sha224',
        64: 'sha256',
        96: 'sha384',
        128: 'sha512'
    }.get(length, None)

# ------------------- Hash Generator ------------------- #
def generate_hash(password, algorithm):
    try:
        func = get_hash_function(algorithm)
        hashed = func(password)
        print(colored(f"[✓] {algorithm.upper()} hash of '{password}':\n{hashed}", "cyan"))
    except Exception as e:
        print(colored(f"[-] Error: {e}", "red"))

# ------------------- Optimized Offline Cracker ------------------- #
def crack_password(hash_str, wordlist_path):
    algorithm = identify_hash_type(hash_str)
    if not algorithm:
        print(colored("[-] Could not identify hash type.", "red"))
        return

    print(colored(f"[*] Identified Hash Type: {algorithm.upper()}", "yellow"))

    try:
        func = get_hash_function(algorithm)
        found = False
        total_lines = sum(1 for _ in open(wordlist_path, 'r', errors='ignore'))

        with open(wordlist_path, 'r', errors='ignore') as file:
            start_time = time.time()
            for i, line in enumerate(file, 1):
                password = line.strip()
                elapsed = time.time() - start_time
                rate = i / elapsed if elapsed else 0
                remaining = (total_lines - i) / rate if rate else 0
                eta = elapsed + remaining

                sys.stdout.write("\033[F\033[K" * 3)  # Clear 3 lines
                print(f'Trying: "{password}"')
                print(f'{round((i/total_lines)*100)}% done... | {i:,} / {total_lines:,}')
                print(f'Remaining time: {time.strftime("%M:%S", time.gmtime(remaining))} / Estimated total: {time.strftime("%M:%S", time.gmtime(eta))}')
                sys.stdout.flush()

                if func(password) == hash_str:
                    print(colored(f"\n[+] Password found: {password}", "green"))
                    found = True
                    break

        if not found:
            print(colored("\n[-] Password not found in wordlist.", "red"))

    except FileNotFoundError:
        print(colored(f"[-] Wordlist file not found: {wordlist_path}", "red"))

# ------------------- Main Menu ------------------- #
def main():
    check_dependencies()
    print_banner()
    print(colored("[1] Generate a hash", "yellow"))
    print(colored("[2] Crack a hash using wordlist", "yellow"))
    print(colored("[0] Exit", "yellow"))

    choice = input(colored("Select an option: ", "cyan"))
    default_wordlist = "/usr/share/wordlists/rockyou.txt"

    if choice == '1':
        password = input("Enter the text to encrypt: ")
        print("\nSelect Hash Algorithm:")
        print("[1] MD5")
        print("[2] SHA1")
        print("[3] SHA224")
        print("[4] SHA256")
        print("[5] SHA384")
        print("[6] SHA512")
        print("[7] NTLM")
        algo_choice = input("Enter choice: ")
        algorithms = {
            '1': 'md5',
            '2': 'sha1',
            '3': 'sha224',
            '4': 'sha256',
            '5': 'sha384',
            '6': 'sha512',
            '7': 'ntlm'
        }
        algo = algorithms.get(algo_choice)
        if not algo:
            print(colored("[-] Invalid algorithm selection.", "red"))
            return
        generate_hash(password, algo)

    elif choice == '2':
        hash_input = input("Enter hash to crack: ")
        wordlist_path = input(f"Enter wordlist file path [default: {default_wordlist}]: ") or default_wordlist
        crack_password(hash_input.strip(), wordlist_path)

    elif choice == '0':
        print(colored("[+] Exiting ShadowCrack. Stay stealthy.", "green"))
        exit()

    else:
        print(colored("[-] Invalid choice.", "red"))

if __name__ == "__main__":
    main()
