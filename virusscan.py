import os
import hashlib
import requests
from time import sleep
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich import print
from dotenv import load_dotenv
from tkinter import Tk, filedialog
from rich.text import Text
from rich.live import Live

# Load environment variables from a .env file (if exists)
load_dotenv()

# Initialize the rich console
console = Console()

# Get VirusTotal API key from environment variables
API_KEY = os.getenv("VT_API_KEY")

def animated_intro():
    """Display a dynamic and animated welcome interface with smooth transitions."""
    intro_text = Text("Welcome to the Malware Hash Scanner Tool!", style="bold yellow on blue")
    intro_subtext = Text(
        "Scan your files or directories for malware using VirusTotal's database.",
        style="italic cyan"
    )
    
    # Display dynamic animation
    with Live(console=console, refresh_per_second=10) as live:
        for _ in range(3):
            intro_text.append(" 🎉")
            live.update(intro_text)
            sleep(0.5)
            intro_text = Text("Welcome to the Malware Hash Scanner Tool!", style="bold yellow on blue")  # Reset the text
            live.update(intro_text)
            sleep(0.5)

        # After animation ends, show the description
        live.update(intro_subtext)
        sleep(1)

        
def show_intro():
    """Display a modern, engaging introduction with a bold design."""
    console.print(
        Panel.fit(
            "[bold yellow]Malware Hash Scanner Tool[/bold yellow]\n"
            "[italic green]Developed by: Aswanth KP[/italic green]\n"
            "[bold cyan]GitHub: [link=https://github.com/0xaswanth]0xaswanth[/link][/bold cyan]",
            title="Welcome to the Scanner",
            border_style="bold magenta"
        )
    )
    animated_intro()

def hash_file(file_path):
    """Calculate the MD5, SHA1, and SHA256 hashes of a file."""
    console.print(f"[bold cyan]Calculating hashes for:[/bold cyan] {file_path}")

    hashes = {"MD5": hashlib.md5(), "SHA1": hashlib.sha1(), "SHA256": hashlib.sha256()}

    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for algo in hashes.values():
                    algo.update(chunk)

        return {name: algo.hexdigest() for name, algo in hashes.items()}

    except Exception as e:
        console.print(f"[bold red]Error reading file:[/bold red] {e}")
        return None

def check_virus_total(hash_value, hash_type):
    """Check a hash against VirusTotal."""
    if not API_KEY:
        console.print("[bold red]VirusTotal API key not found! Please set the API key using environment variables or a .env file.[/bold red]")
        return None

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        analysis_stats = result['data']['attributes']['last_analysis_stats']
        detections = result['data']['attributes']['last_analysis_results']
        return analysis_stats, detections
    elif response.status_code == 404:
        console.print(f"[bold yellow]{hash_type} hash not found in VirusTotal database.[/bold yellow]")
    else:
        console.print(f"[bold red]Error contacting VirusTotal API: {response.status_code}[/bold red]")
    return None, None

def upload_to_virus_total(file_path):
    """Upload a file to VirusTotal for scanning."""
    if not API_KEY:
        console.print("[bold red]VirusTotal API key not found! Please set the API key using environment variables or a .env file.[/bold red]")
        return None

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY}
    with open(file_path, "rb") as file:
        files = {'file': file}
        response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        result = response.json()
        scan_id = result['data']['id']
        console.print(f"[bold green]File uploaded successfully. Scan ID:[/bold green] {scan_id}")
        return scan_id
    else:
        console.print(f"[bold red]Failed to upload file to VirusTotal: {response.status_code}[/bold red]")
        return None

def check_scan_result(scan_id):
    """Check the scan result on VirusTotal using the scan ID."""
    url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
    headers = {"x-apikey": API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        status = result['data']['attributes']['status']

        if status == "completed":
            return result['data']['attributes']['stats'], result['data']['attributes']['results']
        else:
            return None, None
    else:
        console.print(f"[bold red]Error fetching scan result: {response.status_code}[/bold red]")
        return None, None

def scan_file(file_path):
    """Scan a single file for malware using its hashes."""
    hashes = hash_file(file_path)
    if hashes:
        console.print(f"[bold cyan]Scanning {file_path} on VirusTotal...[/bold cyan]")

        hash_found = False
        for hash_type, hash_value in hashes.items():
            analysis_stats, detections = check_virus_total(hash_value, hash_type)
            if analysis_stats:
                display_analysis_result(file_path, hash_type, analysis_stats, detections)
                hash_found = True
                break

        if not hash_found:
            console.print(f"[bold yellow]No hash found for {file_path}.[/bold yellow]")
            upload_choice = console.input("[bold yellow]Would you like to upload the file to VirusTotal for scanning? (y/n): [/bold yellow]").strip().lower()
            if upload_choice == 'y':
                with console.status("[bold cyan]Uploading file to VirusTotal...[/bold cyan]") as status:
                    scan_id = upload_to_virus_total(file_path)
                    if scan_id:
                        result = None
                        with console.status("[yellow]Waiting for VirusTotal to complete the scan...[/yellow]") as status:
                            while not result:
                                result = check_scan_result(scan_id)
                                if not result:
                                    sleep(10)  # Wait for 10 seconds before checking again
                        display_analysis_result(file_path, "Uploaded file", result)
    else:
        console.print(f"[bold red]Failed to calculate hashes for {file_path}.[/bold red]")

def scan_directory(directory_path):
    """Scan all files in a directory."""
    console.print(f"[bold cyan]Scanning directory: {directory_path}[/bold cyan]")

    with Progress() as progress:
        task = progress.add_task("[yellow]Scanning files...", total=len(os.listdir(directory_path)))
        
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_file(file_path)
                progress.update(task, advance=1)

def display_analysis_result(file_name, scan_type, analysis_stats, detections):
    """Display the result of the VirusTotal analysis in a sleek, easy-to-read table."""
    table = Table(title=f"VirusTotal Analysis for {file_name} ({scan_type})", show_lines=True, border_style="bright_yellow")

    table.add_column("Category", style="cyan", justify="right")
    table.add_column("Count", style="magenta", justify="center")

    for category, count in analysis_stats.items():
        table.add_row(category.capitalize(), str(count))

    console.print(table)

    # If the file is detected as malicious, display the virus name
    if 'Malicious' in detections and detections['Malicious']:
        console.print("[bold red]Malicious file detected![/bold red]")
        for engine, detection in detections['Malicious'].items():
            console.print(f"[red]{engine}[/red]: {detection['result']}")
        delete_choice = console.input("[bold red]Would you like to delete the malicious file? (y/n): [/bold red]").strip().lower()
        if delete_choice == 'y':
            try:
                os.remove(file_name)
                console.print(f"[bold green]File deleted successfully: {file_name}[/bold green]")
            except Exception as e:
                console.print(f"[bold red]Error deleting file: {e}[/bold red]")
    else:
        console.print("[green]No malicious detections found.[/green]")

def select_file_or_directory():
    """Open a file dialog to select a file or directory."""
    root = Tk()
    root.withdraw()  # Hide the root window

    choice = console.input("[bold yellow]Do you want to scan a [bold cyan]file[/bold cyan] or [bold cyan]directory[/bold cyan]? (f/d): [/bold yellow]").strip().lower()

    if choice == 'f':
        file_path = filedialog.askopenfilename(title="Select a File to Scan")
        if file_path:
            return file_path
        else:
            console.print("[bold red]No file selected. Exiting.[/bold red]")
            return None
    elif choice == 'd':
        directory_path = filedialog.askdirectory(title="Select a Directory to Scan")
        if directory_path:
            return directory_path
        else:
            console.print("[bold red]No directory selected. Exiting.[/bold red]")
            return None
    else:
        console.print("[bold red]Invalid choice. Please enter 'f' for file or 'd' for directory.[/bold red]") 
        return None

def main():
    """Main function to run the Malware Hash Scanner tool."""
    # Display introduction
    show_intro()

    # Ask user for input (file or directory)
    selected_path = select_file_or_directory()
    
    if selected_path:
        if os.path.isfile(selected_path):
            scan_file(selected_path)
        elif os.path.isdir(selected_path):
            scan_directory(selected_path)
        else:
            console.print("[bold red]Invalid file or directory selected. Exiting.[/bold red]")

    # Goodbye message with animation
    console.print("[bold cyan]Thank you for using the Malware Hash Scanner Tool! Stay safe![/bold cyan]")

if __name__ == "__main__":
    main()
