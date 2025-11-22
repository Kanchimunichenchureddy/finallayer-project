import re

# Read the file
with open('backend/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace verify_password function
old_verify = '''def verify_password(plain_password, hashed_password):
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)'''

new_verify = '''def verify_password(plain_password, hashed_password):
    """Verify a password against its hash"""
    # Bcrypt has a 72-byte limit, truncate if necessary
    password_bytes = plain_password.encode('utf-8')[:72]
    return pwd_context.verify(password_bytes.decode('utf-8'), hashed_password)'''

content = content.replace(old_verify, new_verify)

# Replace get_password_hash function
old_hash = '''def get_password_hash(password):
    """Hash a password"""
    return pwd_context.hash(password)'''

new_hash = '''def get_password_hash(password):
    """Hash a password"""
    # Bcrypt has a 72-byte limit, truncate if necessary
    password_bytes = password.encode('utf-8')[:72]
    return pwd_context.hash(password_bytes.decode('utf-8'))'''

content = content.replace(old_hash, new_hash)

# Write back
with open('backend/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed auth.py successfully!")
