# SCA Security Benchmark Report: Comparative Analysis of Security Tools

**Date:** February 22, 2026  
**Code Analyzed:** SCATest.py (Flask - Python)  
**Total Real Vulnerabilities:** 12  
**Reference:** This report uses verified vulnerability data from [Vulnerabilities Reference](Vulnerabilities.md)

---

## Executive Summary

This report presents a rigorous comparative analysis of 5 security tools:

- **Fortify** (Traditional SAST)
- **Gemini 3 Flash Pro**
- **DeepSeek**
- **ChatGPT**
- **Claude Sonnet 4.6**

### Key Metrics

| Tool | Detected | Precision | Critical | High | Medium | Low |
|------|----------|-----------|----------|------|--------|-----|
| **Fortify** | 2 | 0% | 0 | 2 | 0 | 0 |
| **Gemini** | 8 | 67% | 3 | 3 | 2 | 0 |
| **DeepSeek** | 11 | 92% | 4 | 5 | 2 | 0 |
| **ChatGPT** | 11 | 92% | 3 | 5 | 3 | 0 |
| **Claude** | 13 | 100% | 4 | 7 | 2 | 1 |

---

## Benchmark Charts

### Chart 1: Vulnerability Distribution by Severity

![Distribution](docs/images/grafico1_distribucion.png)

### Chart 2: Detection Precision

![Precision](docs/images/grafico2_precision.png)

### Chart 3: Detection Heatmap by Category

![Heatmap](docs/images/grafico3_heatmap.png)

### Chart 4: Visual Comparison

![Comparison](docs/images/grafico4_comparacion.png)

---

## Detailed Detection Table

| ID | Vulnerability | Severity | Fortify | Gemini | DeepSeek | ChatGPT | Claude |
|----|---------------|----------|---------|--------|----------|---------|--------|
| 1 | Hardcoded Secret | Medium | ✓ | ✓ | ✓ | ✓ | ✓ |
| 2 | SQL Injection | Critical | ✗ | ✓ | ✓ | ✓ | ✓ |
| 3 | Weak Hashing (MD5) | Medium | ✗ | ✓ | ✗ | ✓ | ✓ |
| 4 | Path Traversal | High | ✗ | ✓ | ✓ | ✓ | ✓ |
| 5 | SSTI | Critical | ✗ | ✓ | ✓ | ✓ | ✓ |
| 6 | Command Injection | Critical | ✗ | ✓ | ✓ | ✓ | ✓ |
| 7 | Insecure Deserialization | Critical | ✗ | ✓ | ✓ | ✓ | ✓ |
| 8 | SSRF | High | ✗ | ✓ | ✓ | ✓ | ✓ |
| 9 | Open Redirect | Medium | ✗ | ✓ | ✓ | ✓ | ✓ |
| 10 | Authorization Flaw | High | ✗ | ✓ | ✓ | ✓ | ✓ |
| 11 | TOCTOU/Race Condition | Low | ✗ | ✗ | ✓ | ✓ | ✓ |
| 12 | Debug Mode | High | ✗ | ✓ | ✓ | ✓ | ✓ |

---

## Failure Analysis

### Fortify - 10 vulnerabilities not detected

| ID | Vulnerability | Severity | OWASP Category | Failure Reason |
|----|---------------|----------|----------------|----------------|
| 2 | SQL Injection | Critical | OWASP A03 | Did not detect SQL interpolation with % formatting |
| 3 | Weak Hashing (MD5) | Medium | OWASP A02 | Did not detect MD5 without secret |
| 4 | Path Traversal | High | OWASP A01 | Did not detect defective path validation |
| 5 | SSTI | Critical | OWASP A03 | Did not detect Jinja2 injection |
| 6 | Command Injection | Critical | OWASP A03 | Did not detect OS command injection |
| 7 | Insecure Deserialization | Critical | OWASP A08 | Did not detect insecure deserialization |
| 8 | SSRF | High | OWASP A10 | Did not detect lack of URL validation |
| 9 | Open Redirect | Medium | OWASP A01 | Did not detect defective logic |
| 10 | Authorization Flaw | High | OWASP A01 | Did not detect authorization bypass |
| 11 | TOCTOU/Race Condition | Low | Race Condition | Did not detect race condition |
| 12 | Debug Mode | High | OWASP A05 | Did not detect debug mode |

### LLMs - Individual Failures

| ID | Vulnerability | Tool | Failure Reason |
|----|---------------|------|----------------|
| 3 | Weak Hash (MD5) | DeepSeek | Did not detect use of MD5 without secret |
| 11 | TOCTOU/Race Condition | Gemini | Did not detect race condition |

---

## Statistical Analysis

### Descriptive Statistics

| Metric | Value |
|--------|-------|
| Total Real Vulnerabilities | 12 |
| Mean Detection (LLMs) | 10.8 |
| Standard Deviation (LLMs) | 2.1 |
| Best Tool | Claude (100%) |
| Worst Tool | Fortify (0%) |
| Average Precision (all) | 70% |

### Vulnerabilities by OWASP Category

| OWASP Category | Count | Predominant Severity |
|----------------|-------|----------------------|
| A01 - Broken Access Control | 3 | High |
| A02 - Cryptographic Failures | 2 | Medium |
| A03 - Injection | 4 | Critical |
| A05 - Security Misconfiguration | 1 | High |
| A08 - Software/Data Integrity Failures | 1 | Critical |
| A10 - Server-Side Request Forgery | 1 | High |

---

## References

### Security Tools

1. **Fortify** - Micro Focus Fortify Static Code Analyzer
   - Official: https://www.microfocus.com/en-us/products/static-code-analysis-sast/overview

2. **Gemini** - Google Gemini
   - Official: https://gemini.google.com/

3. **DeepSeek** - DeepSeek LLM
   - Official: https://www.deepseek.com/

4. **ChatGPT** - OpenAI ChatGPT
   - Official: https://chat.openai.com/

5. **Claude** - Anthropic Claude
   - Official: https://www.anthropic.com/claude

### Vulnerability Standards

1. **OWASP Top 10** - Open Web Application Security Project
   - Official: https://owasp.org/www-project-top-ten/

2. **CWE** - Common Weakness Enumeration
   - Official: https://cwe.mitre.org/

3. **CVE** - Common Vulnerabilities and Exposures
   - Official: https://cve.mitre.org/

### Verified Vulnerabilities Reference

All vulnerabilities in this benchmark have been verified and documented in:
- [Vulnerabilities.md](Vulnerabilities.md)

---

## Conclusions

### Key Findings

1. **LLMs significantly outperform Fortify**: Claude, DeepSeek, and ChatGPT achieved +90% precision vs 0% for Fortify

2. **Claude leads the benchmark**: 100% precision, detecting all real vulnerabilities

3. **Fortify failed completely**: Only detected hardcoded secrets (static rule), failed on all critical vulnerabilities

4. **LLM variability**: 
   - Claude: 100% 
   - DeepSeek: 92% 
   - ChatGPT: 92% 
   - Gemini: 67% (missed TOCTOU)

### Implications

- **For critical security**: Use Claude or DeepSeek/ChatGPT
- **For compliance**: Combine Fortify + LLMs
- **For quick analysis**: Gemini (67% in less time)

---

## Recommendations

### Immediate Actions

1. Replace Fortify with LLMs for complex vulnerability analysis
2. Implement pipeline with multiple LLMs for complete coverage
3. Keep Fortify only for regulatory compliance

### Best Practices

1. Use Claude for deep analysis
2. Combine results from multiple tools
3. Manually validate critical findings

---

## Appendix: Vulnerability Details

### Real Vulnerabilities (Verified Reference)

For detailed information on each vulnerability, see [Vulnerabilities.md](Vulnerabilities.md)

1. **Hardcoded Secret** - CWE-798 / OWASP A02
2. **SQL Injection** - CWE-89 / OWASP A03
3. **Weak Hashing (MD5)** - CWE-327 / OWASP A02
4. **Path Traversal** - CWE-22 / OWASP A01
5. **SSTI** - CWE-94 / OWASP A03
6. **Command Injection** - CWE-78 / OWASP A03
7. **Insecure Deserialization** - CWE-502 / OWASP A08
8. **SSRF** - CWE-918 / OWASP A10
9. **Open Redirect** - CWE-601 / OWASP A01
10. **Authorization Flaw** - CWE-287 / OWASP A01
11. **TOCTOU/Race Condition** - CWE-362 / OWASP A01
12. **Debug Mode** - CWE-11 / OWASP A05

---

*Report automatically generated - 2026-02-22*
*Research and Analysis: Marcelo Ernesto Burgos Cayupil*

## Future Work

This benchmark is designed to be expanded with future versions:

- **Additional Vulnerable Code Samples**: New versions with different frameworks (Django, FastAPI, Node.js, etc.)
- **More Security Tools**: Integration of additional SAST tools and LLMs
- **Dynamic Analysis**: Integration of dynamic analysis tools (DAST)
- **Comprehensive Testing**: Larger sample size for statistically significant results
- **Multi-language Support**: Vulnerable code in multiple programming languages
- **Real-world Scenarios**: Analysis of real-world vulnerable applications
