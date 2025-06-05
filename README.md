# Daily System Health Reporter

## Project Description

The Daily System Health Reporter is a Python script designed to automatically gather comprehensive system health metrics, generate a detailed HTML report, and email it to specified recipients. This tool is particularly useful for IT administrators and users who need to monitor the status of their Windows systems regularly.

## Features

*   **Comprehensive System Metrics:**
    *   CPU usage (overall, per core, frequency)
    *   Memory usage (physical and swap)
    *   Disk usage (total, used, free, I/O per partition) with alerts for low space.
    *   System uptime.
    *   Network interface details (IP addresses, speed, data sent/received).
    *   List of currently logged-in users.
    *   Total number of running processes.
    *   Top 5 processes by CPU and memory consumption.
*   **Windows-Specific Monitoring:**
    *   Status of critical Windows services (configurable).
    *   Windows Firewall status.
*   **HTML Reporting:**
    *   Generates a well-formatted and easy-to-read HTML report.
    *   Highlights potential issues like low disk space or stopped services.
*   **Email Notifications:**
    *   Automatically sends the HTML report as an email attachment.
    *   Supports SMTP authentication and TLS encryption.
*   **Configurable:**
    *   Easily configure report directory, email settings (server, port, sender, recipients), and services to monitor via variables in the script.

## Requirements

*   **Python 3.x**
*   **Libraries:**
    *   `psutil`: For gathering system and process information.
    *   `wmi` (Windows-specific): For Windows service monitoring and firewall status. Install using `pip install wmi`.
    *   Standard libraries: `platform`, `smtplib`, `email`, `datetime`, `os`, `getpass`, `time`.

## Configuration

Before running the script, you need to configure the following variables at the beginning of `daily_health_report.py`:

1.  **`REPORT_DIR`**: The directory where HTML reports will be saved.
    *   Example for Windows: `"C:\Temp\ITReports"`
    *   Example for Linux/macOS: `"/tmp/ITReports"` (Note: Some features are Windows-specific)
2.  **Email Settings:**
    *   `SMTP_SERVER`: Your SMTP server address (e.g., `"smtp.gmail.com"`).
    *   `SMTP_PORT`: The SMTP port (e.g., `587` for TLS, `465` for SSL).
    *   `FROM_EMAIL`: The sender's email address.
    *   `TO_EMAILS`: A list of recipient email addresses (e.g., `["admin@example.com", "user@example.com"]`).
    *   `EMAIL_SUBJECT`: The subject line for the email.
    *   `EMAIL_USERNAME`: Your email address for SMTP authentication.
3.  **Email Password (Security Note):**
    *   **WARNING:** Storing passwords directly in scripts is insecure.
    *   The script attempts to get the email password in the following order:
        1.  From the environment variable `EMAIL_PASSWORD`.
        2.  If not found, it will prompt for the password when run manually.
    *   For automated execution, set the `EMAIL_PASSWORD` environment variable.
4.  **`SERVICES_TO_MONITOR` (Windows-specific):**
    *   A list of Windows service *display names* to check.
    *   Example: `["Print Spooler", "Windows Update", "Remote Desktop Services"]`
    *   You can find these names in the Windows Services console (`services.msc`).

## Usage

1.  **Ensure all requirements are installed.**
    *   `pip install psutil`
    *   On Windows: `pip install wmi`
2.  **Configure the script** as described in the "Configuration" section.
3.  **Run the script** from your terminal:
    ```bash
    python daily_health_report.py
    ```
4.  The HTML report will be saved to the `REPORT_DIR`, and if email settings are configured correctly and a password is provided, an email with the report will be sent.

## Platform Support

*   **Core system metrics (CPU, memory, disk, network, processes):** Cross-platform (Windows, Linux, macOS).
*   **Service monitoring and Firewall status:** Currently Windows-specific (using WMI). The script includes placeholders for Linux service status, which are not yet implemented.
*   **HTML Report Generation & Emailing:** Cross-platform.

## Contributing

Contributions are welcome! If you have suggestions for improvements or new features, feel free to:

1.  Fork the repository.
2.  Create a new branch for your feature or bug fix.
3.  Make your changes.
4.  Submit a pull request.

## License

This project is currently not licensed. You may use it at your own risk. Consider adding an open-source license like MIT if you plan to share it widely.
