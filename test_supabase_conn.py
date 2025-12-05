# debug_supabase_env.py
import os, sys
print("Python:", sys.executable)
print(".cwd:", os.getcwd())
print("SUPABASE_URL present:", bool(os.getenv("SUPABASE_URL")))
print("SUPABASE_URL:", (os.getenv("SUPABASE_URL") or "")[:80])
print("SUPABASE_KEY present:", bool(os.getenv("SUPABASE_KEY")))
print("WORKING DIR files:", list(sorted(os.listdir('.')) )[:20])

# If python-dotenv available, try loading .env explicitly
try:
    from dotenv import load_dotenv
    print("python-dotenv available: yes")
    load_dotenv(dotenv_path=".env")
    print("After load_dotenv -> SUPABASE_URL present:", bool(os.getenv("SUPABASE_URL")))
except Exception as e:
    print("python-dotenv available: no", e)

# Attempt Supabase client creation (safe guard)
try:
    from supabase import create_client
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    print("Attempting create_client with URL present:", bool(url), "KEY present:", bool(key))
    if url and key:
        client = create_client(url, key)
        print("create_client succeeded")
    else:
        print("Skipping create_client because URL/KEY missing")
except Exception as e:
    print("create_client error:", repr(e))
