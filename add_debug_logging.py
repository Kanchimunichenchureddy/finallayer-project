import re

# Read the file
with open('backend/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add debug logging to get_password_hash
old_hash_func = re.search(r'def get_password_hash\(password\):.*?return pwd_context\.hash\(password\)', content, re.DOTALL)
if old_hash_func:
    old_text = old_hash_func.group(0)
    new_text = '''def get_password_hash(password):
    """Hash a password"""
    logger.info(f"Hashing password of length: {len(password)}, bytes: {len(password.encode('utf-8'))}")
    # Bcrypt has a 72-byte limit, truncate at byte level
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        logger.warning(f"Password too long ({len(password_bytes)} bytes), truncating to 72 bytes")
        # Truncate and decode, handling potential UTF-8 boundary issues
        password_bytes = password_bytes[:72]
        # Try to decode, if it fails, truncate one more byte
        while len(password_bytes) > 0:
            try:
                password = password_bytes.decode('utf-8')
                break
            except UnicodeDecodeError:
                password_bytes = password_bytes[:-1]
    logger.info(f"Final password length: {len(password)}, bytes: {len(password.encode('utf-8'))}")
    return pwd_context.hash(password)'''
    
    content = content.replace(old_text, new_text)

# Write back
with open('backend/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Added debug logging to password hashing!")
