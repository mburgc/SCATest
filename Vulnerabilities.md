# Verified Vulnerabilities Reference

This document contains the complete list of verified vulnerabilities found in `SCATest.py`. Each vulnerability is documented with its location, severity, category, impact, and detection difficulty.

---

## Vulnerability List

### 1. Hardcoded Secret

**Location:** `SCATest.py:13`

```python
app.secret_key = "prod_key_2024_internal"
```

**Category:** OWASP A02 / A07 - Cryptographic Failures / Security Misconfiguration  
**Severity:** Medium  
**Problem:** Secret embedded in source code → session compromise if repository is exposed.  
**SAST Detectability:** High

---

### 2. SQL Injection (Indirect)

**Location:** `SCATest.py:31` (function `get_user`)

```python
def get_user(u):
    conn = db()
    c = conn.cursor()
    q = "SELECT id, username, password FROM users WHERE username = '%s'" % u
    r = c.execute(q).fetchone()
    conn.close()
    return r
```

**Category:** OWASP A03 - Injection  
**Severity:** Critical  
**Problem:** Direct string interpolation using `%` formatting in SQL query.  
**Data Flow:** `request.form` → `normalize()` → `get_user()` → `execute()`  
**SAST Detectability:** High (if Fortify follows interprocedural dataflow)

---

### 3. Weak Hashing (MD5 for Token)

**Location:** `SCATest.py:38-39` (function `compute_token`)

```python
def compute_token(data):
    raw = json.dumps(data)
    return hashlib.md5(raw.encode()).hexdigest()
```

**Category:** OWASP A02 - Cryptographic Failures  
**Severity:** Medium  
**Problem:** MD5 is cryptographically broken and insecure for tokens.  
**SAST Detectability:** High

---

### 4. Path Traversal (Subtle Bypass)

**Location:** `SCATest.py:42-48` (function `read_local`)

```python
def read_local(name):
    base = os.path.abspath("storage")
    path = os.path.abspath(os.path.join(base, name))
    if base in path:
        with open(path) as f:
            return f.read()
    return ""
```

**Category:** OWASP A01 - Broken Access Control  
**Severity:** High  
**Problem:** The check `if base in path` is incorrect. It uses substring matching instead of proper path boundary validation.

**Bypass Example:**
```
name = "../../etc/passwd"
```

If the final path contains the string "storage" anywhere, it passes the check.  
**Correct validation should be:**
```python
if path.startswith(base + os.sep):
```

**SAST Detectability:** Medium (some tools don't detect defective validation)

---

### 5. Server-Side Template Injection (SSTI)

**Location:** `SCATest.py:77` (route `/view`)

```python
@app.route("/view")
def view():
    t = request.args.get("t", "hi")
    return render_template_string("<div>%s</div>" % t)
```

**Category:** OWASP A03 - Injection  
**Severity:** Critical  
**Problem:** User input injected directly into Jinja template.  
**Example Payload:** `{{7*7}}` returns `49`  
**Impact:** Information disclosure, potentially RCE via Jinja sandbox escapes.  
**SAST Detectability:** Medium-High

---

### 6. Command Injection (Indirect)

**Location:** `SCATest.py:55-57` (function `system_call`)

```python
def system_call(x):
    cmd = "echo %s" % x
    return subprocess.getoutput(cmd)
```

**Category:** OWASP A03 - Injection  
**Severity:** Critical  
**Problem:** User input directly interpolated into shell command.  
**Data Flow:** `request.args` → `system_call` → `subprocess.getoutput`  
**Example Payload:**
```
/run?x=hello; id
```

**SAST Detectability:** High

---

### 7. Insecure Deserialization

**Location:** `SCATest.py:60-61` (function `deserialize`)

```python
def deserialize(blob):
    return pickle.loads(base64.b64decode(blob))
```

**Category:** OWASP A08 - Software and Data Integrity Failures  
**Severity:** Critical  
**Problem:** `pickle.loads()` executes arbitrary Python code during unpickling.  
**Impact:** RCE if malicious payload is provided.  
**SAST Detectability:** High (direct rule)

---

### 8. Server-Side Request Forgery (SSRF)

**Location:** `SCATest.py:51-52` (function `fetch_remote`)

```python
def fetch_remote(u):
    return requests.get(u, timeout=2).text
```

**Category:** OWASP A10 - Server-Side Request Forgery  
**Severity:** High  
**Problem:** No validation of URL scheme, internal IP, or metadata endpoint.

**Example:**
```
/proxy?url=http://169.254.169.254/latest/meta-data/
```

**SAST Detectability:** Medium (some tools only detect basic patterns)

---

### 9. Open Redirect (Defective Logic)

**Location:** `SCATest.py:105-110` (route `/next`)

```python
@app.route("/next")
def go():
    n = request.args.get("n")
    if n and n.startswith("/"):
        return redirect(n)
    return redirect(n)
```

**Category:** OWASP A01 - Broken Access Control  
**Severity:** Medium  
**Problem:** The validation doesn't change behavior. It always redirects regardless of the check.  
**Example:**
```
/next?n=https://evil.com
```

**SAST Detectability:** Medium (requires logical analysis)

---

### 10. Authorization Logic Flaw

**Location:** `SCATest.py:113-118` (route `/admin`)

```python
@app.route("/admin")
def admin():
    role = request.args.get("role")
    if role == "admin" or role == 1:
        return "ok"
    return "denied"
```

**Category:** OWASP A01 - Broken Access Control  
**Severity:** High  
**Problem:** 
- `request.args` always returns a string
- Mixes string/int comparison → conceptual error
- No real authentication

**Example:**
```
/admin?role=admin
```

**SAST Detectability:** Low (SAST rarely detects logic flaws)

---

### 11. TOCTOU / Race Condition

**Location:** `SCATest.py:121-127` (route `/tmp`)

```python
@app.route("/tmp")
def tmp():
    data = request.args.get("d")
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(data.encode())
    f.close()
    return open(f.name).read()
```

**Category:** Security Misconfiguration / Race Condition  
**Severity:** Low  
**Problem:** Time-of-check to time-of-use (TOCTOU) vulnerability. Window between write and reopen. File can be replaced in shared systems.  
**SAST Detectability:** Low

---

### 12. Debug Mode in Production

**Location:** `SCATest.py:131`

```python
if __name__ == "__main__":
    app.run(debug=True)
```

**Category:** OWASP A05 - Security Misconfiguration  
**Severity:** High  
**Problem:** Debug mode enables Werkzeug interactive debugger.  
**Impact:** RCE if exposed (attacker can execute arbitrary Python code).  
**SAST Detectability:** High

---

## Summary: SAST Detection Difficulty

| Vulnerability | Fortify Difficulty |
|--------------|-------------------|
| SQL Injection | Easy |
| Command Injection | Easy |
| Insecure Deserialization | Easy |
| Hardcoded Secret | Easy |
| Weak Hash | Easy |
| SSTI | Medium |
| SSRF | Medium |
| Path Traversal (defective check) | Medium |
| Open Redirect (logical) | Medium |
| Authorization flaw | Difficult |
| TOCTOU | Difficult |
| Debug mode | Easy |

---

## References

- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **CWE Top 25:** https://cwe.mitre.org/top25/
- **CVE Database:** https://cve.mitre.org/

---

*Document generated - February 22, 2026*

*Research and Analysis: Marcelo Ernesto Burgos Cayupil*
