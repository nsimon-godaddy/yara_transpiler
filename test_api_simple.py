import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

API_URL = "https://caas.api.godaddy.com/v1/prompts"
JWT = os.getenv('JWT')

headers = {
    "Authorization": "sso-jwt " + JWT,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

data = {
    "prompt": "test prompt",
    "isPrivate": True,
    "provider": "anthropic_chat",
    "providerOptions": { "model":"claude-3-5-haiku-20241022-v1:0"}
}

response = requests.post(API_URL, headers=headers, json=data)
print(response.json())
