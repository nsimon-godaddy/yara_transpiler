#!/usr/bin/env python3
"""
Debug script to check JWT token and API URL loading
"""

import os
from dotenv import load_dotenv

print("🔍 Debugging JWT Token and API URL Loading")
print("=" * 50)

# Check environment before loading .env
print("📋 Environment BEFORE load_dotenv():")
print(f"   JWT: {'SET' if os.getenv('JWT') else 'NOT SET'}")
print(f"   API_URL: {'SET' if os.getenv('API_URL') else 'NOT SET'}")

# Load .env file
print("\n📋 Loading .env file...")
load_dotenv()

# Check environment after loading .env
print("📋 Environment AFTER load_dotenv():")
print(f"   JWT: {'SET' if os.getenv('JWT') else 'NOT SET'}")
if os.getenv('JWT'):
    jwt = os.getenv('JWT')
    print(f"   JWT Preview: {jwt[:50]}...")
    print(f"   JWT Length: {len(jwt)} characters")
    
    # Check if it's the same as shell
    import subprocess
    try:
        shell_jwt = subprocess.check_output(['bash', '-c', 'echo $JWT'], text=True).strip()
        if shell_jwt:
            print(f"   Shell JWT: {shell_jwt[:50]}...")
            print(f"   Match: {'✅ YES' if jwt == shell_jwt else '❌ NO'}")
        else:
            print("   Shell JWT: NOT SET")
    except:
        print("   Shell JWT: Could not check")

print(f"   API_URL: {os.getenv('API_URL')}")

# Test the actual API call
print("\n🧪 Testing API Call...")
try:
    import requests
    
    headers = {
        "Authorization": f"Bearer {os.getenv('JWT')}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "isPrivate": True,
        "provider": "anthropic_chat",
        "providerOptions": {
            "model": "claude-3-5-haiku-20241022-v1:0",
            "max_tokens": 100,
            "temperature": 0.1
        },
        "messages": [
            {
                "role": "user",
                "content": "Say 'Hello World'"
            }
        ]
    }
    
    print(f"   🔧 Making test API call to: {os.getenv('API_URL')}")
    print(f"   🔧 Using JWT: {os.getenv('JWT')[:50]}...")
    
    response = requests.post(
        os.getenv('API_URL'),
        headers=headers,
        json=payload,
        timeout=30
    )
    
    print(f"   📊 Response Status: {response.status_code}")
    print(f"   📊 Response Body: {response.text[:200]}...")
    
    if response.status_code == 200:
        print("   ✅ API call successful!")
    else:
        print(f"   ❌ API call failed: {response.status_code}")
        
except Exception as e:
    print(f"   ❌ API call error: {e}")
