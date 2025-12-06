from werkzeug.security import generate_password_hash

password = "Likhayag@1234"

hashed = generate_password_hash(password, method='scrypt')
print(hashed)
