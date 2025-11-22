import re

# Read the file
with open('backend/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Replace UserResponse class with Pydantic v2 compatible version
old_user_response = '''class UserResponse(BaseModel):
    id: str
    email: str
    firstName: str
    lastName: str
    role: str
    createdAt: datetime
    lastLogin: Optional[datetime] = None'''

new_user_response = '''class UserResponse(BaseModel):
    model_config = {"from_attributes": True}
    
    id: str
    email: str
    firstName: str
    lastName: str
    role: str
    createdAt: datetime
    lastLogin: Optional[datetime] = None'''

content = content.replace(old_user_response, new_user_response)

# Write back
with open('backend/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Updated UserResponse model for Pydantic v2!")
