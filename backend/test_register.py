import requests
import json

# Test registration
url = "http://127.0.0.1:8000/auth/register"
data = {
    "firstName": "Test",
    "lastName": "User",
    "email": "test@example.com",
    "password": "testpassword123"
}

try:
    response = requests.post(url, json=data)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
except Exception as e:
    print(f"Error: {e}")
    print(f"Response text: {response.text if 'response' in locals() else 'No response'}")
