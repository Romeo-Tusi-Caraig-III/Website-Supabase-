# supabase_check.py
import os, sys, traceback, socket, ssl
from dotenv import load_dotenv, find_dotenv

print("== Running supabase_check.py ==")
print("Python executable:", sys.executable)
print("Python version:", sys.version.replace("\n", " "))

# Load dotenv explicitly (if present)
env_path = find_dotenv()
print("Found .env at:", env_path or "NONE")
if env_path:
    load_dotenv(env_path, override=False)

def _mask(s):
    if not s: return None
    s = s.strip()
    if len(s) <= 6: return "***MASKED***"
    return s[:4] + "..." + s[-3:]

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_SERVICE_ROLE = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_ROLE")

print("\n== Env var checks ==")
print("SUPABASE_URL present:", bool(SUPABASE_URL))
print("SUPABASE_KEY present:", bool(SUPABASE_KEY))
print("SUPABASE_SERVICE_ROLE present:", bool(SUPABASE_SERVICE_ROLE))
print("SUPABASE_URL (masked):", _mask(SUPABASE_URL))
print("SUPABASE_KEY (masked):", _mask(SUPABASE_KEY))
print("Env file used:", env_path or "no .env")

print("\n== Raw first/last chars of SUPABASE values (for stray quotes/newlines) ==")
def show_edges(name, val):
    if val is None:
        print(f"{name}: None")
        return
    s = repr(val)
    print(f"{name}: repr startswith {s[:60]!r} ... endswith {s[-60:]!r}")
show_edges("SUPABASE_URL", SUPABASE_URL)
show_edges("SUPABASE_KEY", SUPABASE_KEY)

print("\n== Try importing packages and versions ==")
try:
    import supabase
    print("supabase package imported. version:", getattr(supabase, "__version__", "unknown"))
except Exception as e:
    print("supabase import FAILED:")
    traceback.print_exc()

try:
    import httpx
    print("httpx imported. version:", getattr(httpx, "__version__", "unknown"))
except Exception as e:
    print("httpx import FAILED:")
    traceback.print_exc()

# Try create_client and catch full traceback
if SUPABASE_URL and SUPABASE_KEY:
    print("\n== Attempting create_client() ==")
    try:
        from supabase import create_client
    except Exception as ex:
        print("Import create_client FAILED:")
        traceback.print_exc()
        create_client = None

    if 'create_client' in globals() and create_client:
        try:
            client = create_client(SUPABASE_URL, SUPABASE_KEY)
            print("create_client() -> SUCCESS (client object):", type(client))
            # Try a simple metadata call if available to test connectivity (non-destructive)
            try:
                # This may be different per supabase-py versions; we'll attempt a generic ping
                if hasattr(client, "auth") and hasattr(client.auth, "get_user"):
                    print("client.auth.get_user exists (can attempt authenticated calls)")
                # Also try a simple HTTP probe
                print("Attempting TCP connect to host in SUPABASE_URL to test network...")
                from urllib.parse import urlparse
                u = urlparse(SUPABASE_URL)
                host = u.hostname
                port = 443 if u.scheme == "https" else 80
                print(f"Probing {host}:{port} ...")
                s = socket.create_connection((host, port), timeout=5)
                s.close()
                print("TCP connect OK")
            except Exception as e:
                print("Connectivity test FAILED:")
                traceback.print_exc()
        except Exception as e:
            print("create_client() raised exception:")
            traceback.print_exc()
else:
    print("\nSkipping create_client() attempt because SUPABASE_URL or SUPABASE_KEY missing.")

# Extra: simple HTTPS GET to the base URL to check DNS/SSL (no auth)
try:
    import ssl, socket
    from urllib.parse import urlparse
    if SUPABASE_URL:
        u = urlparse(SUPABASE_URL)
        host = u.netloc or u.path
        if ':' in host:
            host = host.split(':')[0]
        print("\n== Performing simple HTTPS GET to the SUPABASE host (no HTTP client libs) ==")
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
        conn.settimeout(5)
        try:
            conn.connect((host, 443))
            print("TLS handshake succeeded with", host)
        finally:
            conn.close()
except Exception:
    print("HTTPS probe skipped or failed:")
    traceback.print_exc()

print("\n== End of check. Paste the full output here (mask keys) and I'll analyze it. ==")
