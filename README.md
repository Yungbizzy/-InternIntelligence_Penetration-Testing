# -InternIntelligence_Penetration-Testing
# Penetration Testing Report - OWASP Juice Shop

## 1. Setting Up the Testing Environment

### Option 1: Using Docker

#### Update Your System:
```bash
sudo apt update && sudo apt upgrade
```

#### Install Docker:
```bash
sudo apt install docker.io
```

#### Verify the Installation:
```bash
docker --version
```

#### Ensure Docker is Running:
```bash
sudo systemctl start docker
sudo systemctl status docker
```

#### Pull the OWASP Juice Shop Docker Image:
```bash
sudo docker pull bkimminich/juice-shop
```

#### Run the OWASP Juice Shop:
```bash
sudo docker run -d -p 3000:3000 bkimminich/juice-shop
```

#### Verify Running Containers:
```bash
sudo docker ps
```

#### Access the Web Application:
Open a browser and visit:
```
http://localhost:3000
```
![image](https://github.com/user-attachments/assets/0f00c03f-766a-4f89-a442-cec0131c122b)

---

## 2. Reconnaissance Phase

Using Nmap to scan the target for open ports, services, and vulnerabilities.

### TCP Connect Scan (Full Open Scan):
```bash
nmap -p 3000 10.0.2.15
```
**Findings:** Port 3000 is filtered, possibly blocked by a firewall.

### Transfer Protocol Scan:
```bash
nmap -p 3000 -sT 10.0.2.15
```
**Findings:** Port 3000 is open, running a service identified as PPP (Point-to-Point Protocol).

> **Note:** Port 3000 is commonly used by web development frameworks such as Node.js and Ruby on Rails. It is also used in security testing platforms like OWASP Juice Shop.

---

## 3. Vulnerability Assessment Phase

Using OWASP ZAP to identify security vulnerabilities.

### Install OWASP ZAP:
```bash
sudo apt install zaproxy
```

### Launch ZAP:
```bash
zaproxy
```

### Set Target:
Target URL: `http://10.0.2.15:3000`

### Start Scan:
- Navigate to **Automated Scan**
- Click **Attack** to initiate vulnerability scanning.

### Review Results:
**[Vulnerability Scan Report](https://1drv.ms/b/s!Ap9fwwTuWx-oglGZSWRBZgkOfpxG?e=WA9sCq)**
![image](https://github.com/user-attachments/assets/463340d2-3d88-4189-bcd8-d8a3c04cd5ba)

### High-Risk Vulnerability: SQL Injection (SQLite)
- **Impact:** Allows execution of arbitrary SQL queries, leading to unauthorized data access.
- **Mitigation:**
  - Use prepared statements and parameterized queries.
  - Validate and sanitize user inputs.
  - Limit database privileges.
  - Apply security patches and updates.
  - Implement a Web Application Firewall (WAF).

### Medium Risk Vulnerabilities
1. **Content Security Policy (CSP) Header Not Set** - Risk of XSS attacks.
2. **Cross-Domain Misconfiguration** - Potential data leakage.
3. **Missing Anti-clickjacking Header** - Vulnerable to clickjacking attacks.
4. **Session ID in URL Rewrite** - Increases risk of session hijacking.
5. **Vulnerable JavaScript Library** - Using outdated libraries poses security risks.

### Low Risk Vulnerabilities
- **Cross-Domain JavaScript Source File Inclusion**
- **Private IP Disclosure**
- **Timestamp Disclosure - Unix**
- **X-Content-Type-Options Header Missing**
- **Information Disclosure - Suspicious Comments**

---

## 4. Exploitation Phase

### Objective: Exploit SQL Injection to Gain Admin Access

#### **Tools Used:**
- **Application:** OWASP Juice Shop
- **Proxy:** Burp Suite (Port: 8080)

#### **Steps:**
1. **Discover Admin Email**
   - Navigate to **Product Review** section.
2. **Configure Proxy in Browser**
   - Set **HTTP Proxy:** `127.0.0.1`, **Port:** `8080`
3. **Capture Login Request with Burp Suite**
   - Submit login form, intercept the request.
4. **Send Request to Burp Suite Intruder**
   - Set attack type: **Sniper**
   - Load SQL Injection payloads from:
   ```bash
   /usr/share/wordlist/wfuzz/injections/SQL.txt
   ```
5. **Start Attack and Analyze Response Length**
6. **Use Identified Payload to Login as Admin**
   - Submit payload in login form to bypass authentication.

### **Key Observations**
- **Successful Payload:** SQL Injection enabled unauthorized admin access.
- **Mitigation:** Implement secure coding practices and database protection.
![image](https://github.com/user-attachments/assets/ecc84b53-b330-4eb7-a546-c046cb018bca)


---

## 5. Reflected Cross-Site Scripting (XSS) Exploit

### Steps to Reproduce:
1. **Purchase an Item** on Juice Shop.
2. **Access the Track Order Page:**
   ```
   172.20.10.2:3001/#/track-result/new?id=4c71-d28a8b6ab5b6a25a
   ```
3. **Inject Malicious Payload:**
   ```
   172.20.10.2:3001/#/track-result/new?id=<iframe src="javascript:alert('xss')">
   ```
   ![image](https://github.com/user-attachments/assets/d7f3e9a2-0dc1-4019-95da-966a06399894)

4. **Observe:** JavaScript alert box appears.

### **Impact:**
- Stealing session cookies.
- Phishing attacks.
- Unauthorized actions on behalf of users.

### **Mitigation:**
- **Input Validation & Sanitization**
- **Output Encoding**
- **Content Security Policy (CSP)**
- **Secure Development Practices**

---

## Conclusion

The penetration test on OWASP Juice Shop uncovered multiple security vulnerabilities. High-risk issues like SQL Injection and XSS demonstrate the potential for severe exploitation. Implementing security best practices—such as input validation, secure session handling, and proper HTTP headers—will enhance the security posture of the application.

### **Recommendations:**
- Implement secure coding practices.
- Apply security patches regularly.
- Use Web Application Firewalls (WAFs).
- Conduct regular penetration tests.
- Educate developers on secure coding principles.

By addressing these vulnerabilities, organizations can protect their applications from evolving cyber threats and maintain trust with users.

  
