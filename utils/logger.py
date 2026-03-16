# utils/logger.py
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def info(msg):
    print(f"{Fore.CYAN}[*] {Style.RESET_ALL}{msg}")

def success(msg):
    print(f"{Fore.GREEN}[+] {Style.RESET_ALL}{msg}")

def warning(msg):
    print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}{msg}")

def error(msg):
    print(f"{Fore.RED}[-] {Style.RESET_ALL}{msg}")

def data(key, value):
    print(f"    └── {Fore.MAGENTA}{key}:{Style.RESET_ALL} {value}")