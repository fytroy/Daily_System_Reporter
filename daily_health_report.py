# daily_health_report.py (EXPANDED with more device metrics)

import psutil
import platform
import wmi # For Windows service monitoring and firewall status
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
import datetime
import os
import getpass # For getting password securely during manual input if needed
import time # For uptime calculation

# --- Configuration ---
REPORT_DIR = "C:\\Temp\\ITReports" # Ensure this directory exists or the script can create it.
# If on Linux/macOS, use a path like '/tmp/ITReports' or '/var/log/ITReports'
# REPORT_DIR = "/tmp/ITReports"

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"       # e.g., smtp.office365.com, smtp.gmail.com
SMTP_PORT = 587                     # Common ports: 25, 465 (SSL), 587 (TLS)
FROM_EMAIL = "roygitongarodney@gmail.com"
TO_EMAILS = ["rodneyroygitonga@gmail.com", "fytpng@gmail.com"] # List of recipient emails
EMAIL_SUBJECT = f"Daily IT System Health Report - {datetime.date.today().strftime('%d-%m-%Y')}"
EMAIL_BODY = "Please find attached the daily IT system health report for today."
EMAIL_USERNAME = "roygitongarodney@gmail.com" # Your email address for SMTP authentication
# EMAIL_PASSWORD = "your_email_password" # WARNING: Storing password directly in script is INSECURE!
                                      # Use environment variables, a secure config management,
                                      # or prompt for input when running manually.

# Services to Monitor (Windows-specific display names)
# You'll need to find the correct service display names for your system.
# On Windows, you can find them in Services (services.msc)
SERVICES_TO_MONITOR = [
    "Print Spooler",
    "Background Intelligent Transfer Service",
    "Windows Update",
    "Server", # 'LanmanServer' service name, but 'Server' display name
    "Remote Desktop Services", # 'TermService' service name, but 'Remote Desktop Services' display name
    "Dnscache", # DNS Client service
    "BFE" # Base Filtering Engine (important for Firewall)
    # Add other critical services relevant to your environment
]

# --- Helper Functions ---
def get_system_metrics():
    """Gathers CPU, Memory, Disk usage, Uptime, Network I/O, and detailed hardware info."""
    metrics = {}

    # CPU Usage
    metrics['cpu_percent'] = psutil.cpu_percent(interval=1) # Get average over 1 second
    metrics['cpu_logical_cores'] = psutil.cpu_count(logical=True)
    metrics['cpu_physical_cores'] = psutil.cpu_count(logical=False)
    cpu_freq = psutil.cpu_freq()
    metrics['cpu_current_freq_mhz'] = round(cpu_freq.current, 2) if cpu_freq else 'N/A'
    metrics['cpu_min_freq_mhz'] = round(cpu_freq.min, 2) if cpu_freq else 'N/A'
    metrics['cpu_max_freq_mhz'] = round(cpu_freq.max, 2) if cpu_freq else 'N/A'

    # Memory Usage
    memory = psutil.virtual_memory()
    metrics['total_memory_gb'] = round(memory.total / (1024**3), 2)
    metrics['used_memory_gb'] = round(memory.used / (1024**3), 2)
    metrics['memory_percent'] = memory.percent

    # Swap Memory Usage
    swap = psutil.swap_memory()
    metrics['total_swap_gb'] = round(swap.total / (1024**3), 2)
    metrics['used_swap_gb'] = round(swap.used / (1024**3), 2)
    metrics['swap_percent'] = swap.percent

    # Disk Usage & I/O
    metrics['disk_info'] = []
    disk_io_counters = psutil.disk_io_counters(perdisk=True)

    for partition in psutil.disk_partitions():
        if 'cdrom' in partition.opts or partition.fstype == '':
            continue
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            io_stats = disk_io_counters.get(partition.device, None)
            
            metrics['disk_info'].append({
                'device': partition.device,
                'mountpoint': partition.mountpoint,
                'total_gb': round(usage.total / (1024**3), 2),
                'used_gb': round(usage.used / (1024**3), 2),
                'free_gb': round(usage.free / (1024**3), 2),
                'percent_used': usage.percent,
                'percent_free': round(100 - usage.percent, 2),
                'read_bytes_gb': round(io_stats.read_bytes / (1024**3), 2) if io_stats else 'N/A',
                'write_bytes_gb': round(io_stats.write_bytes / (1024**3), 2) if io_stats else 'N/A'
            })
        except OSError:
            # Handle cases like inaccessible drives
            continue
    
    # Uptime
    boot_time_timestamp = psutil.boot_time()
    boot_datetime = datetime.datetime.fromtimestamp(boot_time_timestamp)
    now_datetime = datetime.datetime.now()
    uptime_duration = now_datetime - boot_datetime
    metrics['uptime'] = str(uptime_duration).split('.')[0] # Remove microseconds

    # Network Details
    metrics['network_interfaces'] = []
    net_io_counters = psutil.net_io_counters(pernic=True)

    for name, stats in psutil.net_if_stats().items():
        if stats.isup and not name.startswith("Loopback"): # Only consider active non-loopback interfaces
            addrs = psutil.net_if_addrs().get(name, [])
            ipv4_addresses = [addr.address for addr in addrs if addr.family == 2] # AF_INET
            
            # Get IO counters for this interface
            io_stats = net_io_counters.get(name, None)
            bytes_sent = round(io_stats.bytes_sent / (1024**2), 2) if io_stats else 'N/A'
            bytes_recv = round(io_stats.bytes_recv / (1024**2), 2) if io_stats else 'N/A'

            metrics['network_interfaces'].append({
                'name': name,
                'status': 'Up' if stats.isup else 'Down',
                'speed_mbps': stats.speed if stats.speed != 0 else 'N/A', # Speed in Mbps
                'ipv4_addresses': ipv4_addresses if ipv4_addresses else ['N/A'],
                'bytes_sent_mb': bytes_sent,
                'bytes_received_mb': bytes_recv
            })
    
    return metrics

def get_logged_in_users():
    """Returns a list of currently logged-in users."""
    users = psutil.users()
    return [{
        'name': user.name,
        'terminal': user.terminal,
        'host': user.host if user.host else 'Local',
        'started': datetime.datetime.fromtimestamp(user.started).strftime('%Y-%m-%d %H:%M:%S')
    } for user in users]

def get_process_count():
    """Returns the total number of running processes."""
    return len(psutil.pids())

def get_top_processes(by_metric='cpu_percent', limit=5):
    """Returns the top N processes by CPU or Memory usage."""
    process_list = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            pinfo = proc.as_dict(attrs=['pid', 'name', 'cpu_percent', 'memory_info'])
            pinfo['memory_percent'] = round(pinfo['memory_info'].rss / psutil.virtual_memory().total * 100, 2)
            process_list.append(pinfo)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    if by_metric == 'cpu_percent':
        process_list.sort(key=lambda x: x['cpu_percent'], reverse=True)
    elif by_metric == 'memory_percent':
        process_list.sort(key=lambda x: x['memory_percent'], reverse=True)
    
    return process_list[:limit]

def get_windows_security_status():
    """Checks Windows Firewall status (Windows-specific)."""
    security_status = {'firewall_status': 'N/A (Non-Windows OS)'}
    if platform.system() == "Windows":
        try:
            c = wmi.WMI(namespace=r"root\SecurityCenter2")
            firewall_products = c.WmiMonitorEvent(
                wmi_class="__InstanceModificationEvent",
                interval_ms=1000,
                WmiQuery="SELECT * FROM FirewallProduct"
            )
            
            # This query is more direct for a snapshot
            firewall_products = c.FirewallProduct()
            
            # Check if any firewall product is active
            active_firewalls = [fw.displayName for fw in firewall_products if fw.firewallstate == 1] # 1 means enabled/on
            if active_firewalls:
                security_status['firewall_status'] = f"Enabled ({', '.join(active_firewalls)})"
            else:
                security_status['firewall_status'] = "Disabled or Not Detected"
                
            # Alternative for simpler check if the above is too complex:
            # from win32com.client import Dispatch
            # firewall_policy = Dispatch("HNetCfg.FwPolicy2")
            # security_status['firewall_status'] = "Enabled" if firewall_policy.FirewallEnabled[1] else "Disabled" # Domain Profile
            
        except Exception as e:
            security_status['firewall_status'] = f"Error checking firewall: {e}"
            print(f"Warning: Could not check Windows Firewall status: {e}")
    return security_status

def get_service_status_windows(service_names):
    """Gathers status of services on Windows using WMI."""
    service_statuses = []
    try:
        c = wmi.WMI()
        for s_name in service_names:
            try:
                # WMI queries are case-insensitive for service display names.
                services = c.Win32_Service(DisplayName=s_name)
                if services:
                    service = services[0] # Take the first match
                    service_statuses.append({
                        'name': service.Name, # Internal service name
                        'display_name': service.DisplayName,
                        'status': service.State, # e.g., 'Running', 'Stopped'
                        'start_mode': service.StartMode # e.g., 'Auto', 'Manual', 'Disabled'
                    })
                else:
                    service_statuses.append({
                        'name': s_name,
                        'display_name': s_name,
                        'status': "Not Found",
                        'start_mode': "N/A"
                    })
            except Exception as e:
                service_statuses.append({
                    'name': s_name,
                    'display_name': s_name,
                    'status': f"Error: {e}",
                    'start_mode': "N/A"
                })
    except Exception as e:
        print(f"Error initializing WMI: {e}. Make sure 'wmi' library is installed and you have permissions.")
        # Fallback to a simpler check or skip services if WMI fails
        for s_name in service_names:
            service_statuses.append({
                'name': s_name,
                'display_name': s_name,
                'status': "WMI Error / Check Permissions",
                'start_mode': "N/A"
            })
    return service_statuses

def get_service_status_linux(service_names):
    """Placeholder for Linux service status (requires systemd/init.d commands)."""
    service_statuses = []
    for s_name in service_names:
        service_statuses.append({
            'name': s_name,
            'display_name': s_name,
            'status': "N/A (Linux not implemented)",
            'start_mode': "N/A"
        })
    return service_statuses


def generate_html_report(metrics, services, users, process_count, top_cpu_processes, top_mem_processes, security_status):
    """Generates the HTML content for the report."""
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Daily IT System Health Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f4; color: #333; }}
        .container {{ background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #0056b3; border-bottom: 2px solid #eee; padding-bottom: 10px; }}
        h2 {{ color: #0056b3; margin-top: 25px; border-bottom: 1px solid #eee; padding-bottom: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #f2f2f2; color: #555; }}
        .alert-red {{ color: #a94442; font-weight: bold; }} /* For critical alerts */
        .alert-orange {{ color: #8a6d3b; font-weight: bold; }} /* For warnings */
        .status-running {{ color: green; font-weight: bold; }}
        .status-stopped {{ color: red; font-weight: bold; }}
        .status-notfound {{ color: #777; font-weight: bold; }}
        .footer {{ margin-top: 30px; font-size: 0.8em; color: #777; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Daily IT System Health Report - {datetime.datetime.now().strftime('%d %B %Y %H:%M:%S')}</h1>
        <p>This report provides a daily snapshot of the system's health metrics for host: {platform.node()}.</p>

        <h2>System Overview</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Operating System</td><td>{platform.system()} {platform.release()} ({platform.version()})</td></tr>
            <tr><td>System Architecture</td><td>{platform.machine()}</td></tr>
            <tr><td>System Uptime</td><td>{metrics['uptime']}</td></tr>
            <tr><td>Total Running Processes</td><td>{process_count}</td></tr>
            <tr><td>Windows Firewall Status</td><td>{security_status['firewall_status']}</td></tr>
        </table>

        <h2>CPU Details & Usage</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>CPU Cores (Physical)</td><td>{metrics['cpu_physical_cores']}</td></tr>
            <tr><td>CPU Cores (Logical)</td><td>{metrics['cpu_logical_cores']}</td></tr>
            <tr><td>Current CPU Frequency</td><td>{metrics['cpu_current_freq_mhz']} MHz</td></tr>
            <tr><td>Min CPU Frequency</td><td>{metrics['cpu_min_freq_mhz']} MHz</td></tr>
            <tr><td>Max CPU Frequency</td><td>{metrics['cpu_max_freq_mhz']} MHz</td></tr>
            <tr><td>Overall CPU Usage (% Total)</td><td>{metrics['cpu_percent']}%</td></tr>
        </table>

        <h2>Memory Details & Usage</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Physical Memory</td><td>{metrics['total_memory_gb']} GB</td></tr>
            <tr><td>Used Physical Memory</td><td>{metrics['used_memory_gb']} GB</td></tr>
            <tr><td>Physical Memory Usage (%)</td><td>{metrics['memory_percent']}%</td></tr>
            <tr><td>Total Swap/Virtual Memory</td><td>{metrics['total_swap_gb']} GB</td></tr>
            <tr><td>Used Swap/Virtual Memory</td><td>{metrics['used_swap_gb']} GB</td></tr>
            <tr><td>Swap/Virtual Memory Usage (%)</td><td>{metrics['swap_percent']}%</td></tr>
        </table>

        <h2>Disk Usage & I/O</h2>
        <table>
            <tr><th>Drive</th><th>Mountpoint</th><th>Total (GB)</th><th>Used (GB)</th><th>Free (GB)</th><th>Used (%)</th><th>Free (%)</th><th>Read (GB)</th><th>Write (GB)</th></tr>
    """
    for disk in metrics['disk_info']:
        free_space_percent = disk['percent_free']
        used_space_percent = disk['percent_used']
        free_class = ""
        used_class = ""

        if free_space_percent < 10: # Less than 10% free is critical
            free_class = "alert-red"
        elif free_space_percent < 20: # Less than 20% free is warning
            free_class = "alert-orange"
        
        if used_space_percent > 90:
            used_class = "alert-red"
        elif used_space_percent > 80:
            used_class = "alert-orange"

        html_content += f"""
            <tr>
                <td>{disk['device']}</td>
                <td>{disk['mountpoint']}</td>
                <td>{disk['total_gb']}</td>
                <td><span class='{used_class}'>{disk['used_gb']}</span></td>
                <td><span class='{free_class}'>{disk['free_gb']}</span></td>
                <td><span class='{used_class}'>{disk['percent_used']}%</span></td>
                <td><span class='{free_class}'>{disk['percent_free']}%</span></td>
                <td>{disk['read_bytes_gb']}</td>
                <td>{disk['write_bytes_gb']}</td>
            </tr>
        """
    html_content += """
        </table>

        <h2>Network Details</h2>
        <table>
            <tr><th>Interface</th><th>Status</th><th>Speed (Mbps)</th><th>IPv4 Addresses</th><th>Bytes Sent (MB)</th><th>Bytes Received (MB)</th></tr>
    """
    if metrics['network_interfaces']:
        for net_if in metrics['network_interfaces']:
            html_content += f"""
            <tr>
                <td>{net_if['name']}</td>
                <td>{net_if['status']}</td>
                <td>{net_if['speed_mbps']}</td>
                <td>{', '.join(net_if['ipv4_addresses'])}</td>
                <td>{net_if['bytes_sent_mb']}</td>
                <td>{net_if['bytes_received_mb']}</td>
            </tr>
            """
    else:
        html_content += "<tr><td colspan='5'>No active network interfaces found.</td></tr>"
    html_content += """
        </table>

        <h2>Logged-in Users</h2>
        <table>
            <tr><th>Username</th><th>Terminal</th><th>Host</th><th>Login Time</th></tr>
    """
    if users:
        for user in users:
            html_content += f"""
            <tr>
                <td>{user['name']}</td>
                <td>{user['terminal']}</td>
                <td>{user['host']}</td>
                <td>{user['started']}</td>
            </tr>
            """
    else:
        html_content += "<tr><td colspan='4'>No users currently logged in.</td></tr>"
    html_content += """
        </table>

        <h2>Top 5 CPU Consuming Processes</h2>
        <table>
            <tr><th>PID</th><th>Process Name</th><th>CPU Usage (%)</th><th>Memory Usage (%)</th></tr>
    """
    if top_cpu_processes:
        for proc in top_cpu_processes:
            html_content += f"""
            <tr>
                <td>{proc['pid']}</td>
                <td>{proc['name']}</td>
                <td>{proc['cpu_percent']}</td>
                <td>{proc['memory_percent']}</td>
            </tr>
            """
    else:
        html_content += "<tr><td colspan='4'>No processes found or unable to retrieve.</td></tr>"
    html_content += """
        </table>

        <h2>Top 5 Memory Consuming Processes</h2>
        <table>
            <tr><th>PID</th><th>Process Name</th><th>CPU Usage (%)</th><th>Memory Usage (%)</th></tr>
    """
    if top_mem_processes:
        for proc in top_mem_processes:
            html_content += f"""
            <tr>
                <td>{proc['pid']}</td>
                <td>{proc['name']}</td>
                <td>{proc['cpu_percent']}</td>
                <td>{proc['memory_percent']}</td>
            </tr>
            """
    else:
        html_content += "<tr><td colspan='4'>No processes found or unable to retrieve.</td></tr>"
    html_content += """
        </table>

        <h2>Service Status</h2>
        <table>
            <tr><th>Service Name</th><th>Display Name</th><th>Status</th><th>Start Mode</th></tr>
    """
    for service in services:
        status_class = ""
        if service['status'] == "Running":
            status_class = "status-running"
        elif service['status'] == "Stopped":
            status_class = "status-stopped"
        elif "Error" in service['status'] or "Not Found" in service['status']:
            status_class = "status-notfound"
        else:
            status_class = "alert-orange" # For other states like 'Starting', 'Stopping'

        html_content += f"""
            <tr>
                <td>{service['name']}</td>
                <td>{service['display_name']}</td>
                <td><span class='{status_class}'>{service['status']}</span></td>
                <td>{service['start_mode']}</td>
            </tr>
        """
    html_content += f"""
        </table>

        <div class="footer">
            <p>Report generated automatically by Python script on {platform.node()}.</p>
        </div>
    </div>
</body>
</html>
    """
    return html_content

def send_email(html_report_path, email_password=None):
    """Sends the HTML report via email."""
    msg = MIMEMultipart()
    msg['From'] = FROM_EMAIL
    msg['To'] = ", ".join(TO_EMAILS) # Join list into a comma-separated string
    msg['Subject'] = EMAIL_SUBJECT

    msg.attach(MIMEText(EMAIL_BODY, 'plain'))

    # Attach the HTML report
    with open(html_report_path, "rb") as f:
        attach = MIMEApplication(f.read(), _subtype="html")
        attach.add_header('Content-Disposition', 'attachment', filename=os.path.basename(html_report_path))
        msg.attach(attach)

    try:
        print("Connecting to SMTP server...")
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls() # Enable TLS encryption
            if EMAIL_USERNAME and email_password:
                server.login(EMAIL_USERNAME, email_password)
            server.send_message(msg)
        print(f"Email sent successfully to {', '.join(TO_EMAILS)}")
    except smtplib.SMTPAuthenticationError:
        print("SMTP Authentication Error: Check your username and password, or use an App Password.")
    except smtplib.SMTPConnectError as e:
        print(f"SMTP Connection Error: {e}. Check server address and port, and network connectivity.")
    except Exception as e:
        print(f"An error occurred while sending email: {e}")

# --- Main Execution ---
if __name__ == "__main__":
    print("Starting daily health report script...")

    # Ensure report directory exists
    if not os.path.exists(REPORT_DIR):
        print(f"Creating report directory: {REPORT_DIR}")
        os.makedirs(REPORT_DIR)

    report_filename = f"DailyITHealthReport_{datetime.date.today().strftime('%Y%m%d')}.html"
    full_report_path = os.path.join(REPORT_DIR, report_filename)

    # 1. Collect Data
    print("Collecting system performance and general metrics...")
    system_metrics = get_system_metrics()
    logged_in_users = get_logged_in_users()
    total_processes = get_process_count()
    top_cpu_processes = get_top_processes(by_metric='cpu_percent', limit=5)
    top_mem_processes = get_top_processes(by_metric='memory_percent', limit=5)

    print("Checking service status and security...")
    if platform.system() == "Windows":
        service_statuses = get_service_status_windows(SERVICES_TO_MONITOR)
        security_status = get_windows_security_status()
    else:
        print("Warning: Some checks (services, firewall) are Windows-specific. Placeholder used for Linux/macOS.")
        service_statuses = get_service_status_linux(SERVICES_TO_MONITOR)
        security_status = {'firewall_status': 'N/A (Non-Windows OS)'} # Placeholder for non-Windows firewall

    # 2. Generate HTML Report
    print("Generating HTML report...")
    html_report = generate_html_report(system_metrics, service_statuses, logged_in_users, 
                                       total_processes, top_cpu_processes, top_mem_processes, 
                                       security_status)

    with open(full_report_path, "w", encoding="utf-8") as f:
        f.write(html_report)
    print(f"Report saved to: {full_report_path}")

    # 3. Send Email
    email_pass = os.environ.get("EMAIL_PASSWORD") # Try to get from environment variable
    if not email_pass:
        try:
            print("To send email, please enter your email password (this will not be stored):")
            email_pass = getpass.getpass()
        except Exception as e:
            print(f"Could not get password interactively: {e}. Email will not be sent.")
            email_pass = None

    if email_pass:
        send_email(full_report_path, email_pass)
    else:
        print("Email password not provided (or error getting it). Skipping email sending.")

    print("Script finished.")