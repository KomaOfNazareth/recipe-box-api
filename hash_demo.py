from werkzeug.security import generate_password_hash, check_password_hash
from app import hash_password, verify_password

# 1. Pick a fake test password — not one you use anywhere
PASSWORD = "hunter2-test"

# 2. Generate a hash
password_hash = hash_password(PASSWORD)
print("Stored hash:")
print(password_hash)
print()

# 3. Try checking the correct password
print("Correct password check:", verify_password(password_hash, "hunter2-test"))

# 4. Try checking an incorrect password
print("Wrong password check:", verify_password(password_hash, "wrong-password"))