import re

# Read the file
with open('backend/auth.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Add ConfigDict import at the top
if 'from pydantic import BaseModel, EmailStr' in content:
    content = content.replace(
        'from pydantic import BaseModel, EmailStr',
        'from pydantic import BaseModel, EmailStr, ConfigDict'
    )

# Replace UserResponse class with proper Pydantic v2 syntax
old_pattern = r'class UserResponse\(BaseModel\):\s+model_config = \{[^\}]+\}\s+'
new_start = 'class UserResponse(BaseModel):\n    model_config = ConfigDict(from_attributes=True)\n    \n'

# Try to replace if it exists
if re.search(old_pattern, content):
    content = re.sub(old_pattern, new_start, content)
else:
    # If not, replace the original
    content = content.replace(
        'class UserResponse(BaseModel):',
        'class UserResponse(BaseModel):\n    model_config = ConfigDict(from_attributes=True)\n'
    )

# Write back
with open('backend/auth.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed Pydantic v2 configuration!")
