from dotenv import load_dotenv
import os
import requests

# Load environment variables from .env file
load_dotenv()
jwt = os.getenv("JWT")

with open("../data/yara_rules.yar", "r") as f:
    yara_rules = f.read()

JWT = os.getenv("JWT")
API_URL = os.getenv("API_URL")
API_CONFIG_CONSTANTS = {
    "isPrivate": True,
    "provider": "anthropic_chat",
    "providerOptions": {
        "model": "claude-3-5-haiku-20241022-v1:0",
        "max_tokens": 4096
    }
}

HEADERS = {
    "Authorization": "sso-jwt " + JWT,
    "Accept": "application/json",
    "Content-Type": "application/json",
}

prompts = [
    {
        "from": "system",
        "content": "You are a security expert specializing in YARA rules. Your task is to validate a set of given YARA rules"
    },
    {
        "from": "user",
        "content": yara_rules
    }

]

payload = {
    "prompts": prompts,
    **API_CONFIG_CONSTANTS
}

response = requests.post(API_URL, headers=HEADERS, json=payload)
print(response.json()["data"]["value"]["content"])