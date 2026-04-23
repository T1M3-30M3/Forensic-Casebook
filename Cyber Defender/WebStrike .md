# Incident Investigation Report: Web Server Compromise

## Executive Summary
This report presents the findings of a forensic investigation into a cyberattack involving unauthorized web shell upload and attempted data exfiltration. The analysis was conducted using network traffic inspection and HTTP request filtering.

---

## 1. Attacker Origin and Intelligence

```bash
Statistics -> Conversation

http.request.method == "GET"
```

- **Source IP Address:** `117.11.88.124`
- **Originating City:** Tianjin
- **Country:** China

**Analysis:**  
The IP address was identified through traffic analysis. Geolocation lookup confirms the origin as Tianjin, China. This information can be used for geo-blocking and threat intelligence correlation.

---

## 2. Adversary Profiling (User-Agent)
```bash
http.request.method == "GET"
```
- **User-Agent:** Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0


**Analysis:**  
The attacker used a Firefox browser on a Linux system. This setup is commonly associated with penetration testing environments.

- **Filter Used:**  http.request.method == "GET"


---

## 3. Identifying the directory where uploaded files are stored is crucial for locating the vulnerable page and removing any malicious files. Which directory is used by the website to store the uploaded files?
```bash
/reviews/uploads/
```


---

## 4. Vulnerability Exploitation (Web Shell Upload)

- **Malicious File Name:** `simple-backdoor.phtml`

**Analysis:**  
The attacker uploaded a web shell using a POST request. The `.phtml` extension suggests an attempt to bypass file upload restrictions and execute server-side code.

- **Filter Used:**  http.request.method == "POST"

---

## 5. Upload Directory Details

- **Directory Path:** `/uploads/`
- **Server Port:** `8080`

**Analysis:**  
The application stores uploaded files in the `/uploads/` directory, which is accessible via the web server. This allowed the attacker to access and execute the uploaded shell.

---

## 6. Data Exfiltration Attempt

- **Target File:** `/etc/passwd`

**Analysis:**  
The attacker attempted to retrieve the `/etc/passwd` file, which contains system user information. This is typically used for reconnaissance and privilege escalation.

---

## Conclusion

The attack followed a common pattern:
1. Exploitation of file upload vulnerability  
2. Deployment of a web shell  
3. Attempted data exfiltration  

---

## Recommendations

1. **Block Malicious IP**
 - Deny access from `117.11.88.124`

2. **Secure Upload Directory**
 - Remove execution permissions from `/uploads/`
 - Restrict direct access

3. **Improve File Upload Security**
 - Validate MIME types
 - Restrict file extensions
 - Rename uploaded files

4. **Monitoring & Logging**
 - Enable detailed logging
 - Monitor suspicious HTTP requests

---