import logging
import time
import configparser
import smtplib
from email.mime.text import MIMEText
from colorama import init, Fore, Style
import argparse
import subprocess
import re
import threading
import pyshark
from datetime import datetime

# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(filename="netdefl.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Global variables
scan_attempts = {}
brute_force_attempts = {}
blocked_ips = {}  # Keep track of blocked IPs and their expiry times
whitelist = set()
lock = threading.Lock()

# Color definitions
COLOR_CRITICAL = Fore.RED
COLOR_WARNING = Fore.YELLOW
COLOR_INFO = Fore.GREEN
COLOR_RESET = Style.RESET_ALL

# Load configuration
config = configparser.ConfigParser()
config.read('netdef_config.ini')

# Email settings
EMAIL_ENABLED = config.getboolean('email', 'enabled', fallback=False)
EMAIL_FROM = config.get('email', 'from', fallback='')
EMAIL_TO = config.get('email', 'to', fallback='')
EMAIL_SUBJECT = config.get('email', 'subject', fallback='NetSentinel Alert')
SMTP_SERVER = config.get('email', 'smtp_server', fallback='')
SMTP_PORT = config.getint('email', 'smtp_port', fallback=587)
SMTP_USER = config.get('email', 'smtp_user', fallback='')
SMTP_PASSWORD = config.get('email', 'smtp_password', fallback='')

# Thresholds
SYN_THRESHOLD = config.getint('thresholds', 'syn_threshold', fallback=10)
PORT_SCAN_THRESHOLD = config.getint('thresholds', 'port_scan_threshold', fallback=20)
BRUTE_FORCE_THRESHOLD = config.getint('thresholds', 'brute_force_threshold', fallback=5)
BLOCK_DURATION = config.getint('thresholds', 'block_duration', fallback=60)

# Whitelist
whitelist.update(config.get('whitelist', 'ips', fallback='').split(','))

# Stop event to signal the thread to stop
stop_event = threading.Event()

def send_email(subject, body):
    if not EMAIL_ENABLED:
        return

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
    except Exception as e:
        logging.error(f"Error sending email: {e}")

def summarize_packet(packet):
    try:
        src_ip = packet.ip.src if "ip" in packet else "Unknown"
        dst_ip = packet.ip.dst if "ip" in packet else "Unknown"
        protocol = packet.highest_layer
        return f"{src_ip} -> {dst_ip} [{protocol}]"
    except AttributeError:
        return "[Incomplete packet]"

def analyze_packet(packet):
    try:
        src_ip = packet.ip.src if "ip" in packet else None
        summary = summarize_packet(packet)

        if not src_ip or src_ip in whitelist:
            return

        # Check if IP is already blocked
        if is_ip_blocked(src_ip):
            return

        # Check for SYN flood
        if "tcp" in packet and packet.tcp.flags_syn == "1" and packet.tcp.flags_ack == "0":
            with lock:
                scan_attempts[src_ip] = scan_attempts.get(src_ip, 0) + 1
                if scan_attempts[src_ip] > SYN_THRESHOLD:
                    print(f"{COLOR_CRITICAL}Potential SYN flood detected from {src_ip}: {summary}{COLOR_RESET}")
                    logging.warning(f"Potential SYN flood detected from {src_ip}: {summary}")
                    block_ip(src_ip, BLOCK_DURATION)
                    send_email(EMAIL_SUBJECT, f"Potential SYN flood detected from {src_ip}: {summary}")

        # Check for port scans
        if "tcp" in packet:
            dst_port = packet.tcp.dstport
            with lock:
                if src_ip not in scan_attempts:
                    scan_attempts[src_ip] = {"ports": set()}
                scan_attempts[src_ip]["ports"].add(dst_port)

                if len(scan_attempts[src_ip]["ports"]) > PORT_SCAN_THRESHOLD:
                    print(f"{COLOR_CRITICAL}Potential port scan detected from {src_ip}: {summary}{COLOR_RESET}")
                    logging.warning(f"Potential port scan detected from {src_ip}: {summary}")
                    block_ip(src_ip, BLOCK_DURATION)
                    send_email(EMAIL_SUBJECT, f"Potential port scan detected from {src_ip}: {summary}")

        # Check for potential brute-force attacks
        if "tcp" in packet and packet.tcp.dstport == "22":
            if re.search(r"Failed password", str(packet)):
                with lock:
                    brute_force_attempts[src_ip] = brute_force_attempts.get(src_ip, 0) + 1
                    if brute_force_attempts[src_ip] > BRUTE_FORCE_THRESHOLD:
                        print(f"{COLOR_WARNING}Potential brute-force attack detected from {src_ip}: {summary}{COLOR_RESET}")
                        logging.warning(f"Potential brute-force attack detected from {src_ip}: {summary}")
                        block_ip(src_ip, BLOCK_DURATION)
                        send_email(EMAIL_SUBJECT, f"Potential brute-force attack detected from {src_ip}: {summary}")

    except AttributeError:
        pass

def is_ip_blocked(ip_address):
    with lock:
        if ip_address in blocked_ips:
            if blocked_ips[ip_address] > time.time():
                return True
            else:
                del blocked_ips[ip_address]
        return False

def block_ip(ip_address, duration):
    with lock:
        if is_ip_blocked(ip_address):
            return

        print(f"{COLOR_CRITICAL}Blocking IP address {ip_address} for {duration} seconds...{COLOR_RESET}")
        logging.info(f"Blocking IP address {ip_address} for {duration} seconds...")
        blocked_ips[ip_address] = time.time() + duration

        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        except subprocess.CalledProcessError as e:
            print(f"{COLOR_CRITICAL}Error blocking IP: {e}{COLOR_RESET}")
            logging.error(f"Error blocking IP: {e}")

def unblock_ips():
    with lock:
        now = time.time()
        for ip, expiry in list(blocked_ips.items()):
            if expiry <= now:
                try:
                    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                    print(f"{COLOR_INFO}Unblocked IP address {ip}{COLOR_RESET}")
                    logging.info(f"Unblocked IP address {ip}")
                except subprocess.CalledProcessError as e:
                    print(f"{COLOR_CRITICAL}Error unblocking IP: {e}{COLOR_RESET}")
                    logging.error(f"Error unblocking IP: {e}")
                del blocked_ips[ip]

def monitor_interface(interface):
    try:
        print(f"{Fore.CYAN}Starting NetDef on interface {interface}...{COLOR_RESET}")
        capture = pyshark.LiveCapture(interface=interface)

        # Ensure the capture is properly stopped when the event is set
        for packet in capture.sniff_continuously():
            if stop_event.is_set():  # Check if stop event is triggered
                print(f"{COLOR_WARNING}Stopping NetDef...{COLOR_RESET}")
                capture.close()
                break
            unblock_ips()
            analyze_packet(packet)

    except pyshark.capture.capture.TSharkCrashException as e:
        print(f"{COLOR_CRITICAL}TShark crashed: {e}{COLOR_RESET}")
        logging.error(f"TShark crashed: {e}")
    except KeyboardInterrupt:
        # Handle the KeyboardInterrupt here
        print(f"{COLOR_WARNING}Stopping NetSentinel...{COLOR_RESET}")
        capture.close()  # Ensure the capture is closed properly when interrupted
        logging.info("NetSentinel stopped by user.")

def main():
    parser = argparse.ArgumentParser(description="NetDefender - Network Security Monitoring Tool")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to monitor")
    args = parser.parse_args()

    # Start monitoring in a separate thread
    monitor_thread = threading.Thread(target=monitor_interface, args=(args.interface,))
    monitor_thread.start()

 # Wait for user interrupt (Ctrl+C)
    try:
        while True:  # Keep the main thread alive
            time.sleep(1) # Check stop event periodically
            if stop_event.is_set():
                break
    except KeyboardInterrupt:
        print(f"{COLOR_WARNING}Stopping NetDef...{COLOR_RESET}")
        stop_event.set()  # Signal the thread to stop gracefully
        monitor_thread.join()  # Ensure thread terminates cleanly
    finally:
        print(f"{COLOR_INFO}NetDef Stopped.{COLOR_RESET}")



if __name__ == "__main__":
    main()
