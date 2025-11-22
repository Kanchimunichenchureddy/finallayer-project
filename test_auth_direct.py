import sys
sys.path.insert(0, 'backend')

from auth import get_password_hash, UserRegistration
from datetime import datetime

# Test password hashing directly
try:
    password = "testpassword123"
    print(f"Testing password hashing for: {password}")
    hashed = get_password_hash(password)
    print(f"Hash successful: {hashed[:50]}...")
    
    # Test creating a user
    user_data = UserRegistration(
        firstName="Test",
        lastName="User",
        email="test@example.com",
        password="testpassword123"
    )
    print(f"\nUser data created: {user_data}")
    
    # Test the full registration flow
    from auth import register
    import asyncio
    
    async def test_register():
        try:
            result = await register(user_data)
            print(f"\nRegistration successful: {result}")
        except Exception as e:
            print(f"\nRegistration failed: {e}")
            import traceback
            traceback.print_exc()
    
    asyncio.run(test_register())
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
