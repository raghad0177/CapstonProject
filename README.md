# Security Vulnerability Assessment & Mitigation Guide
Overview
This project involves the identification and analysis of security vulnerabilities in two servers, Ubuntu and Rana. The vulnerabilities discovered include local privilege escalation, remote code execution, and SQL injection, along with the implementation of mitigations for each vulnerability.

# Part 1: Vulnerability Analysis
1. GNU Screen 4.5.0 - Local Privilege Escalation (EDB-ID 41154)
Overview: Allows local users to gain root privileges by exploiting improper logfile permission checks.
Explanation: The use of the -L flag creates a logfile (ld.so.preload) without proper permission checks.
Mitigation: Update GNU Screen to the latest version with proper permission checks for logfiles.
2. Maltrail v0.53 – Unauthenticated OS Command Injection (EDB-ID 51676)
Overview: Maltrail version 0.52 allows unauthenticated OS command execution via the username input.
Explanation: Exploiting unsanitized input, attackers can execute arbitrary commands via a reverse shell.
Mitigation: Update to the latest version of Maltrail, or configure shell=False to prevent command execution.
3. WordPress Plugin SQL Injection (CVE-2021-24931)
Overview: The 'sccp_id' parameter in the Secure Copy Content Protection and Content Locking plugin is vulnerable to SQL injection.
Explanation: Lack of input sanitization enables both authenticated and unauthenticated users to alter SQL queries.
Mitigation: Update the plugin to the latest version that includes input sanitization using intval() and esc_sql().

#Part 2: Environment Design and Setup
Architecture
Public IP: 86.108.18.89
Gateway: 192.168.1.1
Subnet Mask: 255.255.255.0
Device Information:
Device Name	MAC Address	IP Address
Ubuntu	00:0c:29:08:36:22	192.168.1.47
Rana	00:0c:29:6a:a2
192.168.1.122
Raghad	00:0c:29:7a:7a
192.168.1.116

#Part 3: Services Configuration
VM1 - Ubuntu Server Services
1. FTP Server (vsftpd)
Purpose: Secure file transfers between a client and a server.
Installation Steps:
Install vsftpd: sudo apt-get install vsftpd
Enable and start the service:
sudo systemctl enable vsftpd
sudo systemctl start vsftpd
Configure /etc/vsftpd.conf:
Allow anonymous login: anonymous_enable=YES
Set passive ports: pasv_enable=YES, pasv_min_port=10400, pasv_max_port=10410
3. Maltrail (v0.53)
Purpose: IDS for detecting and tracking network traffic with malicious activity.
Installation Steps:
Download from GitHub: Maltrail v0.53
Unzip and allow incoming connections on port 8338: sudo ufw allow 8338
4. MySQL Database
Purpose: Store and retrieve structured data using relational databases.
Installation Steps:
Install MySQL: sudo apt-get install mysql-server
Start and enable: sudo systemctl enable mysql, sudo systemctl start mysql
Secure MySQL: mysql_secure_installation
5. Apache HTTP Server
Purpose: Serve web content over HTTP.
Installation Steps:
Install Apache: sudo apt-get install apache2
Start and enable: sudo systemctl enable apache2, sudo systemctl start apache2
6. SSH (OpenSSH)
Purpose: Secure remote access to servers.
Installation Steps:
Install OpenSSH: sudo apt-get install openssh-server
Start and enable: sudo systemctl enable ssh, sudo systemctl start ssh

# Part 4: Offensive Cybersecurity - Vulnerability Exploitation
Ubuntu Server Vulnerabilities:
SQL Injection in WordPress plugin Secure Copy Content Protection.
Weak Passwords in MySQL and WordPress admin accounts.
MD5 Hash Usage for storing passwords in MySQL.
Rana Server Vulnerabilities:
FTP Unauthorized Access due to anonymous login.
Maltrail Command Injection via the login page.
GNU Screen Privilege Escalation due to improper logfile permission checks.

# Part 5: Mitigation and Prevention
1. Strong Password Policies:
Enforce complex passwords for all user accounts (mix of uppercase, lowercase, numbers, and symbols).
Implement rate limiting for login attempts.
2. Update Vulnerable Software:
Update WordPress Plugins to latest versions.
Update GNU Screen and disable unnecessary SUID root permissions.
3. Secure FTP Server:
Disable anonymous login and enable user authentication.
Enable logging to monitor file access.
4. Maltrail Security:
Update Maltrail to prevent OS command injections.
If unable to update, set shell=False to mitigate remote command execution.

# Conclusion
This project aimed to identify, exploit, and mitigate security vulnerabilities in both the Ubuntu and Rana servers. By following the recommendations and updating critical software, the system's security has been greatly improved. Continuous monitoring and regular updates are crucial to maintaining a secure environment.

