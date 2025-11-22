import re

# Read the file
with open('backend/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace the password hashing functions to use bcrypt directly
new_functions = '''# Utility functions
def verify_password(plain_password, hashed_password):
    """Verify a password against its hash"""
    try:
        # Bcrypt requires bytes
        password_bytes = plain_password.encode('utf-8')
        # Bcrypt has a 72-byte limit
        if len(password_bytes) > 72:
            password_bytes = password_bytes[:72]
        hash_bytes = hashed_password.encode('utf-8') if isinstance(hashed_password, str) else hashed_password
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def get_password_hash(password):
    """Hash a password"""
    try:
        # Bcrypt requires bytes
        password_bytes = password.encode('utf-8')
        # Bcrypt has a 72-byte limit
        if len(password_bytes) > 72:
            password_bytes = password_bytes[:72]
        # Generate salt and hash
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
    except Exception as e:
        logger.error(f"Password hashing error: {e}")
        raise'''

# Find and replace the utility functions section
pattern = r'# Utility functions\ndef verify_password.*?return pwd_context\.hash\(password\)'
content = re.sub(pattern, new_functions, content, flags=re.DOTALL)

# Write back
with open('backend/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Replaced password functions to use bcrypt directly!")
