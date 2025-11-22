import sys
sys.path.insert(0, 'backend')

# Simple test
try:
    from passlib.context import CryptContext
    
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    def get_password_hash(password):
        """Hash a password"""
        # Bcrypt has a 72-byte limit, truncate if necessary
        password_bytes = password.encode('utf-8')[:72]
        return pwd_context.hash(password_bytes.decode('utf-8'))
    
    # Test it
    password = "testpassword123"
    print(f"Testing password: {password}")
    hashed = get_password_hash(password)
    print(f"Success! Hash: {hashed[:50]}...")
    
    # Test with a very long password
    long_password = "a" * 100
    print(f"\nTesting long password ({len(long_password)} chars)")
    hashed2 = get_password_hash(long_password)
    print(f"Success! Hash: {hashed2[:50]}...")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
