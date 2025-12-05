import os
print("SUPABASE_URL:", bool(os.getenv('SUPABASE_URL')), os.getenv('SUPABASE_URL'))
print("SUPABASE_KEY:", bool(os.getenv('SUPABASE_KEY')))
print("FLASK_DEBUG:", os.getenv('FLASK_DEBUG'))