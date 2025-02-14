import subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.progress import TaskID, TextColumn, Progress, BarColumn
from rich.table import Column


lock = threading.Lock()  # Lock for writing to the result file

sema = threading.Semaphore(value=5)

def check_ssh_connection(host, port, username, password, timeout, verbose, retry_count=0):
    """
    Check if SSH connection is successful using the system's sshpass and ssh command.
    Supports retrying after a connection reset.
    """
    if verbose:
        print(f"Trying {username}:{password} on {host}:{port}")
    try:
        # Construct the sshpass command to pass the password and run the ssh command
        command = [
            "sshpass", 
            "-p", password,  # Password for SSH
            "ssh", 
            "-o", f"ConnectTimeout={timeout}",  # Set the connection timeout
            "-o", "StrictHostKeyChecking=no",  # Automatically accept host keys
            "-o", "PasswordAuthentication=yes",  # Ensure password authentication is used
            "-o", "KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group-exchange-sha256",
            "-o", "Ciphers=+aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc",
            "-o", "MACs=+hmac-sha1,hmac-md5,hmac-sha2-256,hmac-sha2-512",
            "-p", port,  # Port for SSH connection
            f"{username}@{host}",  # Username and host
            "exit"  # Simple command to execute (does nothing)
        ]

        # Run the command using subprocess
        result = subprocess.run(command, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Check if the ssh command was successful
        if result.returncode == 0:
            print(f"[+] Authentication succeeded on {host} ({username}:{password})")
            return f"[+] {host}  => {username}:{password}"
        elif result.returncode == 255:  # SSH connection reset or error
            if retry_count < 3:
                wait_time = [20, 40, 60][retry_count]  # Retry times (20, 40, 60 seconds)
                if verbose:
                    print(f"Connection reset on {host}. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)  # Wait before retrying
                return check_ssh_connection(host, port, username, password, timeout, verbose, retry_count + 1)
            else:
                if verbose:
                    print(f"[!] Maximum retries reached for {host} ({username}:{password})")
                return f"[!] Maximum retries reached for {host} ({username}:{password})"
        else:
            return None  # Return None if authentication failed for another reason

    except Exception as e:
        print(e)
        return f"[!] Error connecting to {host} ({username}:{password}): {e}"

def pre_check(host, port, timeout, verbose):
    try:
        # Construct the sshpass command to pass the password and run the ssh command
        command = [
            "sshpass", 
            "-p", "a",  # Password for SSH
            "ssh", 
            "-o", f"ConnectTimeout={timeout}",  # Set the connection timeout
            "-o", "StrictHostKeyChecking=no",  # Automatically accept host keys
            "-o", "PasswordAuthentication=yes",  # Ensure password authentication is used
            "-p", port,  # Port for SSH connection
            f"a@{host}",  # Username and host
            "exit"  # Simple command to execute (does nothing)
        ]

        # Run the command using subprocess
        result = subprocess.run(command, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Check if the ssh command was successful
        if result.returncode == 255:
            return False
        
        return True

    except Exception as e:
        print(e)
        return False

def write_to_file(result_file, message, verbose):
    """
    Safely write a message to the result file.
    """
    with lock:
        with open(result_file, "a") as f:
            f.write(message + "\n")

text_column1 = TextColumn("{task.fields[taskid]}", table_column=Column(ratio=1), style= "bold")
text_column2 = TextColumn("{task.fields[status]}", table_column=Column(ratio=1), style= "dim")

progress = Progress(
    text_column1, text_column2, refresh_per_second= 1
)




console = Console()

def process_host2(task_id, ip, port, credentials, result_file, timeout, verbose):
    """
    Function to simulate host processing. Updates thread status dynamically.
    """
    thread_name = threading.current_thread().name
    try:
        progress.update(task_id, status=f"[yellow]Processing {ip}:{port}[/yellow]")
        progress.start_task(task_id)
        if not pre_check(ip, port, timeout, verbose):
            progress.update(task_id, status=f"[red]Precheck Failed {ip}:{port}[/red]")
        else:
            for username, password in credentials:
                message = check_ssh_connection(ip, port, username, password, timeout, verbose)
                if message and message.startswith("[+]"):
                    progress.update(task_id, status=f"[green]Found {ip}:{port} -> {username}:{password}[/green]")
                    write_to_file(result_file, message[4:], verbose)
        
    except Exception as e:
        progress.update(task_id, status=f"[red]Error {ip}:{port}: {e}[/red]")


def main():
    parser = argparse.ArgumentParser(description="Check SSH authentication on servers using sshpass and ssh command.")
    parser.add_argument("hosts_file", help="Path to the input file with host details.")
    parser.add_argument("credentials_file", help="Path to the file with credentials (username:password).")
    parser.add_argument("result_file", default="sshwhirl-output.txt", help="Path to the file where results will be saved.")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout for SSH connections in seconds. (Default = 10)")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads. (Default = 10)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    
    global semaphore
    semaphore = threading.Semaphore(args.threads)



    # Read credentials from the credentials file
    credentials = []
    cred_number = 0
    with open(args.credentials_file, "r") as f:
        for line in f:
            cred_number += 1
            if ":" in line:
                username, password = line.strip().split(":", 1)
                credentials.append((username, password))
                
                
    if args.verbose:
        print(f"{credentials} credentials found")

    # Clear the result file at the start
    with open(args.result_file, "w") as f:
        f.write("")  # Clear contents
        
    max_threads = args.threads

    host_number = 0
    # Read hosts from the input file
    hosts = []
    with open(args.hosts_file, "r") as f:
        for line in f:
            host_number += 1
            line = line.strip()
            port = "22"
            host = line
            if ":" in line:
                host = line.split(":")[0]
                port = line.split(":")[1]
            hosts.append((host, port))
    
    if args.verbose:
        print(f"{host_number} hosts are going to be processed")
    
    with progress:
        with ThreadPoolExecutor(max_threads) as executor:
            task_id = progress.add_task("ZZzzZZ", taskid=f"{host[0]}:{host[1]}", status="status")
            executor.submit(process_host2, task_id, host[0], host[1], credentials, args.result_file, args.timeout, args.verbose)
            # executor.map(lambda host: process_host(host[0], host[1], credentials, args.result_file, args.timeout, args.verbose), hosts)




if __name__ == "__main__":
    main()
