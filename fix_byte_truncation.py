import re

# Read the file
with open('backend/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix verify_password - properly truncate at byte level
old_verify = '''def verify_password(plain_password, hashed_password):
    """Verify a password against its hash"""
    # Bcrypt has a 72-byte limit, truncate the string first
    truncated_password = plain_password[:72] if len(plain_password) > 72 else plain_password
    return pwd_context.verify(truncated_password, hashed_password)'''

new_verify = '''def verify_password(plain_password, hashed_password):
    """Verify a password against its hash"""
    # Bcrypt has a 72-byte limit, truncate at byte level
    password_bytes = plain_password.encode('utf-8')
    if len(password_bytes) > 72:
        # Truncate and decode, handling potential UTF-8 boundary issues
        password_bytes = password_bytes[:72]
        # Try to decode, if it fails, truncate one more byte
        while len(password_bytes) > 0:
            try:
                plain_password = password_bytes.decode('utf-8')
                break
            except UnicodeDecodeError:
                password_bytes = password_bytes[:-1]
    return pwd_context.verify(plain_password, hashed_password)'''

content = content.replace(old_verify, new_verify)

# Fix get_password_hash - properly truncate at byte level
old_hash = '''def get_password_hash(password):
    """Hash a password"""
    # Bcrypt has a 72-byte limit, truncate the string first
    truncated_password = password[:72] if len(password) > 72 else password
    return pwd_context.hash(truncated_password)'''

new_hash = '''def get_password_hash(password):
    """Hash a password"""
    # Bcrypt has a 72-byte limit, truncate at byte level
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        # Truncate and decode, handling potential UTF-8 boundary issues
        password_bytes = password_bytes[:72]
        # Try to decode, if it fails, truncate one more byte
        while len(password_bytes) > 0:
            try:
                password = password_bytes.decode('utf-8')
                break
            except UnicodeDecodeError:
                password_bytes = password_bytes[:-1]
    return pwd_context.hash(password)'''

content = content.replace(old_hash, new_hash)

# Write back
with open('backend/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed password truncation at byte level!")
