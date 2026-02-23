1️⃣ Hardcoded Secret

Ubicación:

app.secret_key = "prod_key_2024_internal"

Categoría: OWASP A02 / A07
Problema: secreto embebido en código → compromiso de sesiones si el repo se filtra.
Detectabilidad SAST: Alta.

2️⃣ SQL Injection (indirecta)

Ubicación: get_user(u)

q = "SELECT id, username, password FROM users WHERE username = '%s'" % u

Categoría: OWASP A03 – Injection
Problema: interpolación directa vía % formatting.
Flujo:
request.form → normalize() → get_user() → execute()
Detectabilidad: Alta (si Fortify sigue dataflow interprocedural).

3️⃣ Weak Hashing (MD5 para token)

Ubicación: compute_token()

return hashlib.md5(raw.encode()).hexdigest()

Categoría: OWASP A02 – Cryptographic Failures
Problema: MD5 inseguro para tokens.
Detectabilidad: Alta.

4️⃣ Path Traversal (bypass sutil)

Ubicación: read_local(name)

base = os.path.abspath("storage")
path = os.path.abspath(os.path.join(base, name))
if base in path:

Problema crítico:
El check if base in path es incorrecto.
Ejemplo bypass:

name = "../../etc/passwd"

Si el path final contiene el string storage en algún punto, pasa el check.

Debería usar:

if path.startswith(base + os.sep)

Categoría: OWASP A01
Detectabilidad: Media (algunas herramientas no detectan validación defectuosa).

5️⃣ Server-Side Template Injection (SSTI)

Ubicación: /view

render_template_string("<div>%s</div>" % t)

Problema:
Entrada del usuario inyectada directamente en plantilla Jinja.
Payload: {{7*7}}
Categoría: OWASP A03
Detectabilidad: Media–Alta.

6️⃣ Command Injection (indirecta)

Ubicación: system_call(x)

cmd = "echo %s" % x
subprocess.getoutput(cmd)

Flujo:
request.args → system_call → subprocess.getoutput

Payload ejemplo:

x=hello; id

Categoría: OWASP A03
Detectabilidad: Alta.

7️⃣ Insecure Deserialization

Ubicación: deserialize(blob)

pickle.loads(base64.b64decode(blob))

Categoría: OWASP A08
Impacto: RCE si payload malicioso.
Detectabilidad: Alta (regla directa).

8️⃣ SSRF

Ubicación: fetch_remote(u)

requests.get(u, timeout=2)

Problema:
No hay validación de esquema, IP interna ni metadata endpoint.

Ejemplo:

http://169.254.169.254/latest/meta-data/

Categoría: OWASP A10
Detectabilidad: Media (algunas herramientas solo detectan patrón básico).

9️⃣ Open Redirect (lógica defectuosa)

Ubicación: /next

if n and n.startswith("/"):
    return redirect(n)
return redirect(n)

Problema:
La validación no cambia el comportamiento.
Siempre redirige.

Categoría: OWASP A01
Detectabilidad: Media (requiere análisis lógico).

🔟 Lógica de autorización defectuosa

Ubicación: /admin

if role == "admin" or role == 1:

Problema sutil:
request.args siempre retorna string.
Pero mezcla comparación string/int → error conceptual.
Además no hay autenticación real.

Categoría: OWASP A01
Detectabilidad: Baja (SAST raramente detecta lógica defectuosa).

1️⃣1️⃣ TOCTOU / Race Condition

Ubicación: /tmp

f = tempfile.NamedTemporaryFile(delete=False)
...
return open(f.name).read()

Problema:
Ventana entre write y reopen.
Archivo puede ser reemplazado en sistemas compartidos.

Categoría: Security Misconfiguration / Race
Detectabilidad: Baja.

1️⃣2️⃣ Debug Mode en producción
app.run(debug=True)

Impacto:
Interactive debugger → RCE si expuesto.
Categoría: OWASP A05
Detectabilidad: Alta.

🔎 Resumen de dificultad para SAST
Vulnerabilidad	Dificultad para Fortify
SQL Injection	Fácil
Command Injection	Fácil
Insecure Deserialization	Fácil
Hardcoded Secret	Fácil
Weak Hash	Fácil
SSTI	Media
SSRF	Media
Path Traversal (check defectuoso)	Media
Open Redirect lógico	Media
Authorization flaw	Difícil
TOCTOU	Difícil
Debug mode	Fácil