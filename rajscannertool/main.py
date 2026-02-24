#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
import ipaddress
import socket
import time
import requests
import concurrent.futures
import threading
from colorama import Fore, Back, Style, init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TaskProgressColumn,
    TimeRemainingColumn, MofNCompleteColumn, TextColumn
)
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
from rich.columns import Columns
from rich import box
from urllib3.exceptions import InsecureRequestWarning

# --- Configuration ---
# Modified for cross-platform compatibility
HOME_DIR = os.path.expanduser("~")
OUTPUT_DIR = os.path.join(HOME_DIR, "RajScan_Results")
SAVE_FILE = os.path.join(OUTPUT_DIR, "extracted_domains.txt")
RESULTS_IP = os.path.join(OUTPUT_DIR, "scanner_ips.txt")
RESULTS_WORD = os.path.join(OUTPUT_DIR, "scanner_results.txt")
CIDR_RESULTS = os.path.join(OUTPUT_DIR, "cidr_results.txt")

# --- Thread Configuration (Default) ---
DEFAULT_THREADS = 500
MIN_THREADS = 80
MAX_THREADS = 500
BATCH_SIZE = 10000
CHUNK_SIZE = 2000

# --- Developer Info ---
DEV_NAME = "Mr. Raj"
YT_CHANNEL = "Mr Tech Hacker"
INSTAGRAM = "@raj_dark_official"
TG_CHANNEL = "Mr Tech Hacker"
GITHUB = "RajownerTech"
WEBSITE = "https://github.com/RajownerTech"

# --- Setup ---
init(autoreset=True)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
console = Console()
lock = threading.Lock()

# Create a session pool for better performance
session_pool = threading.local()

def get_session():
    """Get or create a session for thread-local reuse"""
    if not hasattr(session_pool, 'session'):
        session_pool.session = requests.Session()
        session_pool.session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; Multi-Advance-Tool/1.0)"})
        session_pool.session.verify = False
        adapter = requests.adapters.HTTPAdapter(pool_connections=200, pool_maxsize=200, max_retries=0)
        session_pool.session.mount('http://', adapter)
        session_pool.session.mount('https://', adapter)
    return session_pool.session

def ensure_output_dir():
    """Ensures the output directory exists."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def get_thread_count():
    """Get thread count from user with validation"""
    while True:
        try:
            threads = input(f"{Fore.CYAN}⚡ Enter threads [{MIN_THREADS}-{MAX_THREADS}] (default {DEFAULT_THREADS}): {Style.RESET_ALL}").strip()
            
            if threads == "":
                return DEFAULT_THREADS
            
            threads = int(threads)
            
            if MIN_THREADS <= threads <= MAX_THREADS:
                return threads
            else:
                console.print(f"[bright_red]❌ Threads must be between {MIN_THREADS} and {MAX_THREADS}![/bright_red]")
        except ValueError:
            console.print(f"[bright_red]❌ Please enter a valid number![/bright_red]")

# --- Beautiful Banner ---

def banner():
    """Create an eye-catching banner"""
    console.print()
    console.print("╔══════════════════════════════════════════════════════════╗", style="bright_red")
    console.print("║            ⚡ MULTI-ADVANCE TOOL ⚡                      ║", style="bright_yellow")
    console.print("╠══════════════════════════════════════════════════════════╣", style="bright_cyan")
    console.print("║       Created by Mr Raj | Mr tech hacker                 ║", style="bright_green")
    console.print("║            Advanced Tool fast Scanner v2.0               ║", style="bright_blue")
    console.print("║         [THREADS: 80-500 - USER SELECTABLE]              ║", style="bright_magenta")
    console.print("╚══════════════════════════════════════════════════════════╝", style="bright_red")
    console.print()

# --- Developer Info Function ---

def show_developer_info():
    """Display developer information with social links"""
    console.print(f"\n[bold bright_red]👨‍💻 DEVELOPER INFORMATION[/bold bright_red]")
    console.print(f"[bright_cyan]════════════════════════════════════════════════[/bright_cyan]")
    
    # Create developer profile card
    profile_table = Table(show_header=False, box=box.ROUNDED, border_style="bright_yellow")
    profile_table.add_column("Field", style="bright_cyan", width=15)
    profile_table.add_column("Details", style="bright_white")
    
    profile_table.add_row("👤 Name", f"[bold bright_green]{DEV_NAME}[/bold bright_green]")
    profile_table.add_row("📛 Alias", "Mr. Tech Hacker")
    profile_table.add_row("💼 Role", "Security Researcher & Developer")
    profile_table.add_row("🌍 Location", "India")
    
    console.print(Panel(profile_table, title="[bold bright_red]PROFILE[/bold bright_red]", border_style="bright_cyan"))
    
    # Social Media Links
    console.print(f"\n[bold bright_magenta]📱 SOCIAL MEDIA[/bold bright_magenta]")
    
    social_table = Table(show_header=False, box=box.SIMPLE, border_style="bright_blue")
    social_table.add_column("Platform", style="bright_yellow", width=12)
    social_table.add_column("Link/ID", style="bright_white")
    
    social_table.add_row("📺 YouTube", f"{YT_CHANNEL}")
    social_table.add_row("📸 Instagram", f"{INSTAGRAM}")
    social_table.add_row("📱 Telegram", f"{TG_CHANNEL}")
    social_table.add_row("💻 GitHub", f"{GITHUB}")
    
    console.print(social_table)
    
    # Contact Info
    console.print(f"\n[bold bright_blue]📧 CONTACT[/bold bright_blue]")
    console.print(f"[bright_cyan]├─[/bright_cyan] Email: [bright_yellow]raj.tech.hacker@protonmail.com[/bright_yellow]")
    console.print(f"[bright_cyan]├─[/bright_cyan] Website: [bright_green]{WEBSITE}[/bright_green]")
    console.print(f"[bright_cyan]└─[/bright_cyan] GitHub: [bright_magenta]https://github.com/{GITHUB}[/bright_magenta]")
    
    # Tools & Projects
    console.print(f"\n[bold bright_green]🔧 PROJECTS & TOOLS[/bold bright_green]")
    projects = [
        "• Multi-Advance Tool v2.0 - Current",
        "• Subdomain Scanner Pro",
        "• CIDR Range Exploiter",
        "• Port Scanner Ultra",
        "• Domain Extractor Plus"
    ]
    
    for project in projects:
        console.print(f"  [bright_cyan]{project}[/bright_cyan]")
    
    # Support Message
    console.print(f"\n[bold bright_yellow]⭐ SUPPORT[/bold bright_yellow]")
    console.print(f"[bright_white]If you like this tool, follow on social media for updates![/bright_white]")
    console.print(f"[bright_magenta]Subscribe to YouTube channel for more hacking tools![/bright_magenta]")
    
    input(f"\n[bright_cyan]🔄 Press Enter to return to menu...[/bright_cyan]")

# --- Domain Extractor ---

def extract_domains(text):
    domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
    return set(domain_pattern.findall(text))

def load_existing(filepath):
    if not os.path.exists(filepath):
        return set()
    with open(filepath, 'r') as f:
        return set(line.strip() for line in f if line.strip())

def save_new_domains(new_domains, filepath):
    with open(filepath, 'a') as f:
        for domain in new_domains:
            f.write(domain + '\n')

def run_extractor():
    ensure_output_dir()
    console.print(f"\n[bold bright_red]📋 DOMAIN EXTRACTOR[/bold bright_red]")
    console.print(f"[bright_cyan]──────────────────────────────────────────[/bright_cyan]")
    
    console.print(f"\n[bright_blue]📌 Paste your text below (press Enter twice to extract):[/bright_blue]")
    console.print(f"[bright_yellow]⚡ Tip: You can paste multiple lines at once[/bright_yellow]\n")
    
    lines = []
    blank_count = 0

    while True:  
        try:  
            line = input()  
            if line.strip() == "":  
                blank_count += 1  
                if blank_count == 2:  
                    break  
            else:  
                blank_count = 0  
                lines.append(line)  
        except KeyboardInterrupt:  
            return  

    pasted_text = "\n".join(lines)  
    extracted = extract_domains(pasted_text)  
    existing = load_existing(SAVE_FILE)  
    new = extracted - existing  

    if new:  
        console.print(f"\n[bright_green]✅ SUCCESS! Found {len(new)} new domain(s)[/bright_green]")
        console.print(f"[bright_cyan]📁 Saving to: {SAVE_FILE}[/bright_cyan]")
        console.print(f"\n[bright_blue]📊 Extracted Domains:[/bright_blue]")
        
        for idx, domain in enumerate(sorted(new)[:20], 1):
            console.print(f"  {idx}. {domain}")
        
        if len(new) > 20:
            console.print(f"  ... and {len(new)-20} more domains")
        
        save_new_domains(new, SAVE_FILE)  
    else:  
        console.print(f"[bright_yellow]⚠️ No new domains found.[/bright_yellow]")  

    input(f"\n[bright_cyan]🔄 Press Enter to return to menu...[/bright_cyan]")  
    return

# --- Text Scanner (Host Scanner) with Thread Selection ---

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "N/A"

def scan_head(domain, port, progress, task_id, total_found):
    """Optimized scanner with connection pooling"""
    url = f"http://{domain}:{port}" if port != 443 else f"https://{domain}:{port}"
    ip = "N/A"
    
    try:
        ip = get_ip(domain)
        if ip == "N/A":
            progress.update(task_id, advance=1)
            return

        session = get_session()
        resp = session.head(
            url, timeout=3,
            allow_redirects=False
        )
        
        status = resp.status_code
        server = resp.headers.get("Server", "Unknown")

        if status != 302 and "jio" not in server.lower():
            line = f"{status} | {server[:15]} | {ip} | {domain}:{port}"
            
            if status == 200:
                status_color = "bright_green"
            elif status < 400:
                status_color = "bright_yellow"
            else:
                status_color = "bright_red"
            
            with lock:
                console.print(
                    f"[{status_color}]●[/{status_color}] "
                    f"[{status_color}]{status}[/{status_color}] | "
                    f"[bright_cyan]{server[:15]:15}[/bright_cyan] | "
                    f"[bright_magenta]{ip:15}[/bright_magenta] | "
                    f"[bright_blue]{domain}:{port}[/bright_blue]"
                )
                
                with open(RESULTS_WORD, "a") as f:
                    f.write(line + "\n")
                
                with open(RESULTS_IP, "a") as f:
                    f.write(ip + "\n")
                
                total_found[0] += 1
                
    except Exception:
        pass
    finally:
        progress.update(task_id, advance=1)

def run_text_scanner():
    ensure_output_dir()
    console.print(f"\n[bold bright_red]🔍 HOST SCANNER[/bold bright_red]")
    console.print(f"[bright_cyan]──────────────────────────────────────────[/bright_cyan]")
    
    file_path = input(f"{Fore.YELLOW}📂 Enter path to domain list: {Style.RESET_ALL}").strip()
    if not os.path.exists(file_path):
        console.print(f"[bright_red]❌ File not found![/bright_red]")
        time.sleep(1)
        return

    ports_input = input(f"{Fore.YELLOW}🔌 Enter ports (comma separated, e.g. 80,443,8080): {Style.RESET_ALL}").strip()
    ports = [int(p.strip()) for p in ports_input.split(",")] if ports_input else [80]
    
    threads = get_thread_count()

    with open(file_path, "r") as f:
        domains = [line.strip() for line in f if line.strip()]

    total_tasks = len(domains) * len(ports)
    total_found = [0]

    console.print(f"\n[bright_blue]🚀 Starting scan on {len(domains)} domains with {threads} threads...[/bright_blue]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
        expand=True
    ) as progress:
        task_id = progress.add_task("[bright_cyan]Scanning...", total=total_tasks)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for domain in domains:
                for port in ports:
                    futures.append(executor.submit(scan_head, domain, port, progress, task_id, total_found))
            
            concurrent.futures.wait(futures)

    console.print(f"\n[bold bright_red]📊 SCAN COMPLETE[/bold bright_red]")
    console.print(f"[bright_cyan]──────────────────────────────────────────[/bright_cyan]")
    console.print(f"[bright_green]Total Found:[/bright_green] {total_found[0]}")
    console.print(f"[bright_blue]Results saved to:[/bright_blue] {RESULTS_WORD}")
    
    input(f"\n[bright_cyan]🔄 Press Enter to return to menu...[/bright_cyan]")

# --- CIDR Scanner ---

def scan_cidr_host(ip, port, progress, task_id, total_found):
    url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}:{port}"
    
    try:
        session = get_session()
        resp = session.head(url, timeout=2, allow_redirects=False)
        status = resp.status_code
        server = resp.headers.get("Server", "Unknown")

        if status != 302 and "jio" not in server.lower():
            line = f"{status} | {server[:15]} | {ip} | {ip}:{port}"
            
            if status == 200:
                status_color = "bright_green"
            elif status < 400:
                status_color = "bright_yellow"
            else:
                status_color = "bright_red"
            
            with lock:
                console.print(
                    f"[{status_color}]●[/{status_color}] "
                    f"[{status_color}]{status}[/{status_color}] | "
                    f"[bright_cyan]{server[:15]:15}[/bright_cyan] | "
                    f"[bright_magenta]{ip:15}[/bright_magenta] | "
                    f"[bright_blue]{ip}:{port}[/bright_blue]"
                )
                
                with open(CIDR_RESULTS, "a") as f:
                    f.write(line + "\n")
                
                total_found[0] += 1
                
    except Exception:
        pass
    finally:
        progress.update(task_id, advance=1)

def run_cidr_scanner():
    ensure_output_dir()
    console.print(f"\n[bold bright_red]🌐 CIDR SCANNER[/bold bright_red]")
    console.print(f"[bright_cyan]──────────────────────────────────────────[/bright_cyan]")
    
    cidr = input(f"{Fore.YELLOW}📡 Enter CIDR range (e.g. 1.1.1.0/24): {Style.RESET_ALL}").strip()
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        hosts = [str(ip) for ip in network]
    except ValueError:
        console.print(f"[bright_red]❌ Invalid CIDR range![/bright_red]")
        time.sleep(1)
        return

    ports_input = input(f"{Fore.YELLOW}🔌 Enter ports (comma separated, e.g. 80,443,8080): {Style.RESET_ALL}").strip()
    ports = [int(p.strip()) for p in ports_input.split(",")] if ports_input else [80]
    
    threads = get_thread_count()
    total_ips = len(hosts)
    total_tasks = total_ips * len(ports)
    total_found = [0]

    console.print(f"\n[bright_blue]🚀 Starting CIDR scan on {total_ips} IPs with {threads} threads...[/bright_blue]\n")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
            console=console,
            expand=True
        ) as progress:
            for port in ports:
                task_id = progress.add_task(f"[bright_cyan]Port {port}...", total=total_ips)
                
                for i in range(0, total_ips, CHUNK_SIZE):
                    chunk = hosts[i:i + CHUNK_SIZE]
                    
                    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                        futures = [
                            executor.submit(scan_cidr_host, ip, port, progress, task_id, total_found) 
                            for ip in chunk
                        ]
                        concurrent.futures.wait(futures)
                    
                    progress.update(task_id, description=f"[bright_yellow]Port {port}: {i+len(chunk)}/{total_ips} IPs")
                    time.sleep(0.1)

    except KeyboardInterrupt:
        console.print(f"\n[bright_yellow]⚠️ Scan interrupted[/bright_yellow]")
    except Exception as e:
        console.print(f"\n[bright_red]❌ Error: {e}[/bright_red]")

    console.print(f"\n[bold bright_red]📊 SCAN COMPLETE[/bold bright_red]")
    console.print(f"[bright_cyan]──────────────────────────────────────────[/bright_cyan]")
    console.print(f"[bright_blue]Network Scanned:[/bright_blue] {network}")
    console.print(f"[bright_blue]Total IPs:[/bright_blue] {total_ips:,}")
    console.print(f"[bright_blue]Ports Scanned:[/bright_blue] {', '.join(map(str, ports))}")
    console.print(f"[bright_green]Responsive Hosts:[/bright_green] {total_found[0]:,}")
    
    if total_tasks > 0:
        success_rate = (total_found[0] / total_tasks) * 100
        console.print(f"[bright_yellow]Success Rate:[/bright_yellow] {success_rate:.2f}%")
    
    if total_found[0] > 0:
        console.print(f"\n[bright_green]✅ Results saved to: {CIDR_RESULTS}[/bright_green]")
    
    input(f"\n[bright_cyan]🔄 Press Enter to return to menu...[/bright_cyan]")

# --- Menu ---

def main():
    while True:
        os.system("clear" if os.name == "posix" else "cls")
        banner()
        
        console.print("[bold bright_red]MAIN MENU[/bold bright_red]")
        console.print(f"[bright_cyan]────────────────────[/bright_cyan]")
        console.print(f"[bright_yellow]1.[/bright_yellow] [bright_blue]Host Scanner[/bright_blue]")
        console.print(f"[bright_yellow]2.[/bright_yellow] [bright_blue]CIDR Scanner[/bright_blue] ")
        console.print(f"[bright_yellow]3.[/bright_yellow] [bright_blue]Domain Extractor[/bright_blue]")
        console.print(f"[bright_yellow]4.[/bright_yellow] [bright_magenta]Developer Info[/bright_magenta] 👨‍💻")
        console.print(f"[bright_yellow]0.[/bright_yellow] [bright_blue]Exit[/bright_blue]")
        console.print()
        
        choice = input(f"{Fore.YELLOW}⚡ Choose option [0-4]: {Style.RESET_ALL}").strip()
        
        if choice == "1":
            run_text_scanner()
        elif choice == "2":
            run_cidr_scanner()
        elif choice == "3":
            run_extractor()
        elif choice == "4":
            show_developer_info()
        elif choice == "0":
            console.print(f"\n[bright_green]👋 Thank you for using Multi-Advance Tool![/bright_green]")
            console.print(f"[bright_cyan]Follow {DEV_NAME} on social media for updates![/bright_cyan]")
            break
        else:
            console.print(f"[bright_red]❌ Invalid option! Please choose 0, 1, 2, 3, or 4.[/bright_red]")
            time.sleep(1)

def start():
    try:
        ensure_output_dir()
        main()
    except KeyboardInterrupt:
        console.print("\n⚠️ Exiting...")