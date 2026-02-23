# SCATest - Security Tools Benchmark

A comprehensive benchmark comparing security analysis tools (SAST and LLMs) for vulnerability detection in Python/Flask applications.

## Overview

This project evaluates the effectiveness of various security tools in detecting vulnerabilities in a deliberately vulnerable Flask application (`SCATest.py`). The benchmark compares traditional SAST tools (Fortify) with Large Language Models (LLMs) to determine which approach provides better security analysis.

## Results Summary

| Tool | Precision | Vulnerabilities Detected |
|------|-----------|-------------------------|
| **Claude** | 100% | 13/12 |
| **DeepSeek** | 92% | 11/12 |
| **ChatGPT** | 92% | 11/12 |
| **Gemini** | 67% | 8/12 |
| **Fortify** | 0% | 2/12 |

## Key Findings

- **LLMs significantly outperform traditional SAST** for complex vulnerability detection
- **Claude** achieved 100% precision in detecting all 12 verified vulnerabilities
- **Fortify** failed to detect critical vulnerabilities (RCE, SQLi, SSTI, etc.)
- Only 2 vulnerabilities detected by Fortify vs 8-13 by LLMs

## Project Structure

```
SCATest/
├── SCATest.py           # Vulnerable Flask application (DO NOT USE IN PRODUCTION)
├── Vulnerabilities.md       # Verified vulnerabilities reference
├── PROMPT               # Security analysis prompt used for LLMs
├── README.md            # This file
├── docs/
│   ├── REPORT.md       # Main benchmark report (English)
│   ├── REPORT_ES.md     # Benchmark report (Spanish)
│   └── images/
│       ├── grafico1_distribucion.png
│       ├── grafico2_precision.png
│       ├── grafico3_heatmap.png
│       └── grafico4_comparacion.png
├── SCATest_CWETop25.md  # Fortify analysis results
├── Gemini3FlashPro (Paid Subscription)     # Gemini analysis
├── DeepSeek (Free Standard Subscription)     # DeepSeek analysis
├── ChatGPT (Free Standard Subscription)     # ChatGPT analysis
└── AnthropicClaudeSonnet4.6 (Free Standard Subscription)  # Claude analysis
```

## Vulnerabilities Analyzed

### Critical (4)
1. **SQL Injection** - CWE-89 / OWASP A03
2. **Server-Side Template Injection (SSTI)** - CWE-94 / OWASP A03
3. **Command Injection** - CWE-78 / OWASP A03
4. **Insecure Deserialization** - CWE-502 / OWASP A08

### High (7)
5. **Path Traversal** - CWE-22 / OWASP A01
6. **SSRF** - CWE-918 / OWASP A10
7. **Authorization Flaw** - CWE-287 / OWASP A01
8. **Debug Mode** - CWE-11 / OWASP A05

### Medium (1)
9. **Hardcoded Secret** - CWE-798 / OWASP A02
10. **Weak Hashing (MD5)** - CWE-327 / OWASP A02
11. **Open Redirect** - CWE-601 / OWASP A01

### Low (1)
12. **TOCTOU/Race Condition** - CWE-362 / OWASP A01

See [Vulnerabilities.md](Vulnerabilities.md) for complete details.

## Tools Compared

### Traditional SAST
- **Fortify Static Code Analyzer** - Enterprise SAST tool by Micro Focus

### Large Language Models
- **Claude Sonnet 4.6** - Anthropic
- **ChatGPT** - OpenAI
- **DeepSeek** - DeepSeek
- **Gemini 3 Flash Pro** - Google

## Report

Full benchmark report available in:
- [docs/REPORT.md](docs/REPORT.md) (English)
- [docs/REPORT_ES.md](docs/REPORT_ES.md) (Spanish)

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Fortify Official](https://www.microfocus.com/en-us/products/static-code-analysis-sast/overview)
- [Claude Official](https://www.anthropic.com/claude)
- [ChatGPT Official](https://chat.openai.com/)
- [DeepSeek Official](https://www.deepseek.com/)
- [Gemini Official](https://gemini.google.com/)

## Disclaimer

⚠️ **WARNING**: `SCATest.py` contains intentionally vulnerable code for educational and testing purposes only. **DO NOT DEPLOY** this code in any production environment.

The vulnerable code was deliberately written for security testing and benchmark purposes. Future versions will include additional vulnerable samples in different frameworks and languages.

## Future Work

- **Additional Vulnerable Code Samples**: New versions with different frameworks (Django, FastAPI, Node.js, etc.)
- **More Security Tools**: Integration of additional SAST tools and LLMs
- **Dynamic Analysis**: Integration of dynamic analysis tools (DAST)
- **Comprehensive Testing**: Larger sample size for statistically significant results
- **Multi-language Support**: Vulnerable code in multiple programming languages

## License

MIT License

---

*Last Updated: February 22, 2026*

*Research and Analysis: Marcelo Ernesto Burgos Cayupil*
