import subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

# Semaphore to limit concurrent threads
semaphore = threading.Semaphore(10)  # Adjust as needed

lock = threading.Lock()  # Lock for writing to the result file

def check_ssh_connection(host, port, username, password, timeout, retry_count=0):
    """
    Check if SSH connection is successful using the system's sshpass and ssh command.
    Supports retrying after a connection reset.
    """
    try:
        # Construct the sshpass command to pass the password and run the ssh command
        command = [
            "sshpass", 
            "-p", password,  # Password for SSH
            "ssh", 
            "-o", f"ConnectTimeout={timeout}",  # Set the connection timeout
            "-o", "StrictHostKeyChecking=no",  # Automatically accept host keys
            "-o", "PasswordAuthentication=yes",  # Ensure password authentication is used
            "-p", str(port),  # Port for SSH connection
            f"{username}@{host}",  # Username and host
            "exit"  # Simple command to execute (does nothing)
        ]

        # Run the command using subprocess
        result = subprocess.run(command, text=True, capture_output=True)

        # Check if the ssh command was successful
        if result.returncode == 0:
            return f"[+] SSH authentication succeeded on {host} ({username}:{password})"
        elif result.returncode == 255:  # SSH connection reset or error
            if retry_count < 3:
                wait_time = [30, 60, 90][retry_count]  # Retry times (30, 60, 90 seconds)
                print(f"Connection reset on {host}. Retrying in {wait_time} seconds...")
                time.sleep(wait_time)  # Wait before retrying
                return check_ssh_connection(host, port, username, password, timeout, retry_count + 1)
            else:
                return f"[!] Maximum retries reached for {host} ({username}:{password})"
        else:
            return None  # Return None if authentication failed for another reason

    except Exception as e:
        return f"[!] Error connecting to {host} ({username}:{password}): {e}"


def write_to_file(result_file, message):
    """
    Safely write a message to the result file.
    """
    with lock:
        with open(result_file, "a") as f:
            f.write(message + "\n")


def process_host(host, port, credentials, result_file, timeout):
    """
    Process a single host with all credentials and save results to a file.
    """
    attempt_count = 0  # Counter for login attempts
    with semaphore:
        for username, password in credentials:
            message = check_ssh_connection(host, port, username, password, timeout)
            if message:  # Only write successful logins
                write_to_file(result_file, message)


def main():
    parser = argparse.ArgumentParser(description="Check SSH authentication on servers using sshpass and ssh command.")
    parser.add_argument("hosts_file", help="Path to the input file with host details.")
    parser.add_argument("credentials_file", help="Path to the file with credentials (username:password).")
    parser.add_argument("result_file", help="Path to the file where results will be saved.")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout for SSH connections in seconds.")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads.")
    args = parser.parse_args()

    # Read hosts from the input file
    hosts = []
    with open(args.hosts_file, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 1:
                host = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 22
                hosts.append((host, port))

    # Read credentials from the credentials file
    credentials = []
    with open(args.credentials_file, "r") as f:
        for line in f:
            if ":" in line:
                username, password = line.strip().split(":", 1)
                credentials.append((username, password))

    # Clear the result file at the start
    with open(args.result_file, "w") as f:
        f.write("")  # Clear contents

    # Create a thread pool and process hosts
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for host, port in hosts:
            futures.append(executor.submit(process_host, host, port, credentials, args.result_file, args.timeout))

        # Wait for all threads to complete
        for future in as_completed(futures):
            pass  # You can add logging here if you want to track progress

if __name__ == "__main__":
    main()
