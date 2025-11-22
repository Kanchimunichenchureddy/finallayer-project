import requests
import json
import random

# Test registration with a unique email
url = "http://127.0.0.1:8000/auth/register"
random_num = random.randint(1000, 9999)
data = {
    "firstName": "Test",
    "lastName": "User",
    "email": f"test{random_num}@example.com",
    "password": "test1234"
}

print(f"Testing registration with email: {data['email']}")

try:
    response = requests.post(url, json=data)
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        print(f"Success! Response: {json.dumps(response.json(), indent=2)}")
    else:
        print(f"Failed! Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
