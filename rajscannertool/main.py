#!/usr/bin/env python3
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
OUTPUT_DIR = "/storage/emulated/0/Download/RajScan_Results"
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
    
    input(f"\n🔄 Press Enter to return to menu...")

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

    input(f"\n🔄 Press Enter to return to menu...")  
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
                total_found[0] += 1
                
                if total_found[0] % 100 == 0:
                    try:
                        with open(RESULTS_IP, "a") as ip_file:
                            ip_file.write(f"{ip}\n")
                        with open(RESULTS_WORD, "a") as word_file:
                            word_file.write(f"{line}\n")
                    except:
                        pass
    except:
        pass
    finally:
        progress.update(task_id, advance=1)

def run_text_scanner():
    ensure_output_dir()
    console.print(f"\n[bold bright_red]🔍 HOST SCANNER[/bold bright_red]")
    console.print(f"[bright_cyan]──────────────────────────────────────────[/bright_cyan]")
    
    filename = input(f"{Fore.CYAN}📂 Enter filename containing subdomains: {Style.RESET_ALL}").strip()
    
    if not filename:
        console.print(f"[bright_red]❌ Filename cannot be empty![/bright_red]")
        input(f"\n🔄 Press Enter to return to menu...")
        return
    
    try:
        with open(filename, "r") as f:
            total = sum(1 for line in f if line.strip())
    except FileNotFoundError:
        console.print(f"[bright_red]❌ File '{filename}' not found![/bright_red]")
        input(f"\n🔄 Press Enter to return to menu...")
        return
    
    if total == 0:
        console.print(f"[bright_yellow]⚠️ Input file is empty.[/bright_yellow]")
        input(f"\n🔄 Press Enter to return to menu...")
        return

    try:
        port = int(input(f"{Fore.CYAN}🔌 Enter port (default 443): {Style.RESET_ALL}").strip() or "443")
    except ValueError:
        port = 443

    # Get thread count from user
    threads = get_thread_count()
    console.print(f"[bright_green]⚡ Using {threads} threads for scanning![/bright_green]")

    open(RESULTS_IP, "w").close()
    open(RESULTS_WORD, "w").close()

    total_found = [0] 
    start = time.time()

    console.print(f"\n[bright_cyan]📊 Statistics:[/bright_cyan]")
    console.print(f"  [bright_blue]• Total Domains:[/bright_blue] {total:,}")
    console.print(f"  [bright_blue]• Port:[/bright_blue] {port}")
    console.print(f"  [bright_blue]• Threads:[/bright_blue] {threads}")
    console.print(f"  [bright_blue]• Batch Size:[/bright_blue] {BATCH_SIZE:,}")
    console.print(f"\n[bright_green]🚀 Starting ultra-fast scan...[/bright_green]")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, complete_style="bright_green"),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task_id = progress.add_task(f"[bright_yellow]Scanning domains...", total=total)
            
            with open(filename, "r") as f:
                domain_batch = []
                for line in f:
                    domain = line.strip()
                    if domain:
                        domain_batch.append(domain)
                        
                        if len(domain_batch) >= BATCH_SIZE:
                            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                                futures = [executor.submit(scan_head, d, port, progress, task_id, total_found) for d in domain_batch]
                                concurrent.futures.wait(futures)
                            domain_batch = []
                            time.sleep(0.1)
                
                if domain_batch:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                        futures = [executor.submit(scan_head, d, port, progress, task_id, total_found) for d in domain_batch]
                        concurrent.futures.wait(futures)

    except Exception as e:
        console.print(f"[bright_red]❌ Error during scan: {e}[/bright_red]")

    elapsed = time.time() - start
    rate = total / elapsed if elapsed > 0 else 0

    console.print(f"\n[bold bright_red]📊 FINAL SUMMARY[/bold bright_red]")
    console.print(f"[bright_cyan]──────────────────────────────────────────[/bright_cyan]")
    console.print(f"[bright_blue]Total Scanned:[/bright_blue] {total:,}")
    console.print(f"[bright_green]Responsive Hosts:[/bright_green] {total_found[0]:,}")
    console.print(f"[bright_yellow]Success Rate:[/bright_yellow] {(total_found[0]/total*100):.1f}%")
    console.print(f"[bright_magenta]Time Taken:[/bright_magenta] {elapsed:.2f} seconds")
    console.print(f"[bright_cyan]Speed:[/bright_cyan] {rate:.2f} domains/sec")
    
    console.print(f"\n[bright_green]✅ Results saved to:[/bright_green]")
    console.print(f"  [bright_blue]• {RESULTS_IP}[/bright_blue]")
    console.print(f"  [bright_blue]• {RESULTS_WORD}[/bright_blue]")
    
    input(f"\n🔄 Press Enter to return to menu...")

# --- CIDR Scanner with Thread Selection ---

def scan_cidr_host(ip, port, progress, task_id, total_found):
    """Optimized CIDR scanner"""
    protocols = ['http', 'https']
    session = get_session()
    
    for protocol in protocols:
        url = f"{protocol}://{ip}:{port}"
        try:
            response = session.get(
                url, timeout=2,
                allow_redirects=False
            )
            
            server = response.headers.get('Server', 'Unknown')
            
            if response.status_code != 404 and "404 Not Found" not in response.text:
                with lock:
                    if response.status_code == 200:
                        status_color = "bright_green"
                    elif response.status_code < 400:
                        status_color = "bright_yellow"
                    else:
                        status_color = "bright_red"
                    
                    console.print(
                        f"[{status_color}]●[/{status_color}] "
                        f"[{status_color}]{response.status_code}[/{status_color}] | "
                        f"[bright_cyan]{server[:20]:20}[/bright_cyan] | "
                        f"[bright_magenta]{protocol}[/bright_magenta] | "
                        f"[bright_blue]{ip}:{port}[/bright_blue]"
                    )
                    
                    total_found[0] += 1
                    
                    result_line = f"{response.status_code} | {server} | {protocol}://{ip}:{port}"
                    try:
                        with open(CIDR_RESULTS, "a") as cidr_file:
                            cidr_file.write(f"{result_line}\n")
                    except:
                        pass
                    
                    break
        except:
            continue
    
    progress.update(task_id, advance=1)

def run_cidr_scanner():
    ensure_output_dir()
    console.print(f"\n[bold bright_red]🌐 CIDR SCANNER[/bold bright_red]")
    console.print(f"[bright_cyan]──────────────────────────────────────────[/bright_cyan]")
    
    cidr_input = input(f"{Fore.CYAN}📡 Enter CIDR (e.g., 192.168.1.0/24): {Style.RESET_ALL}").strip()
    
    if not cidr_input:
        console.print(f"[bright_red]❌ CIDR cannot be empty![/bright_red]")
        input(f"\n🔄 Press Enter to return to menu..")
        return
    
    try:
        if '/' in cidr_input:
            network = ipaddress.ip_network(cidr_input, strict=False)
        else:
            network = ipaddress.ip_network(f"{cidr_input}/32", strict=False)
    except ValueError as e:
        console.print(f"[bright_red]❌ Invalid CIDR: {e}[/bright_red]")
        input(f"\n🔄 Press Enter to return to menu...")
        return

    ports_input = input(f"{Fore.CYAN}🔌 Enter ports (comma-separated, default 80,443,8080): {Style.RESET_ALL}").strip()
    if ports_input:
        try:
            ports = [int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()]
        except:
            ports = [80, 443, 8080]
    else:
        ports = [80, 443, 8080]

    # Get thread count from user
    threads = get_thread_count()
    console.print(f"[bright_green]⚡ Using {threads} threads for CIDR scan![/bright_green]")

    open(CIDR_RESULTS, "w").close()

    if network.num_addresses > 65536:
        console.print(f"[bright_yellow]⚠️ Large network detected. This may take a while...[/bright_yellow]")
    
    hosts = [str(ip) for ip in network.hosts()]
    total_ips = len(hosts)
    total_tasks = total_ips * len(ports)
    
    total_found = [0]

    console.print(f"\n[bright_cyan]📊 Scan Configuration:[/bright_cyan]")
    console.print(f"  [bright_blue]• Network:[/bright_blue] {network}")
    console.print(f"  [bright_blue]• Total IPs:[/bright_blue] {total_ips:,}")
    console.print(f"  [bright_blue]• Ports:[/bright_blue] {', '.join(map(str, ports))}")
    console.print(f"  [bright_blue]• Threads:[/bright_blue] {threads} 🔥")
    console.print(f"  [bright_blue]• Chunk Size:[/bright_blue] {CHUNK_SIZE:,}")
    console.print(f"\n[bright_green]🚀 Starting CIDR scan...[/bright_green]")

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, complete_style="bright_green"),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task_id = progress.add_task(f"[bright_yellow]Scanning IPs...", total=total_tasks)
            
            for port in ports:
                console.print(f"\n[bright_cyan]🔍 Scanning port {port}...[/bright_cyan]")
                
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
    
    input(f"\n🔄 Press Enter to return to menu...")

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

if __name__ == "__main__":
    try:
        ensure_output_dir()
        main()
    except KeyboardInterrupt:
        console.print(f"\n[bright_yellow]⚠️ Exiting...[/bright_yellow]")
        console.print(f"[bright_cyan]Follow @raj_dark_official on Instagram![/bright_cyan]")
    except Exception as e:
        console.print(f"\n[bright_red]❌ Fatal Error: {e}[/bright_red]")