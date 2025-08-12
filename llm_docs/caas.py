from dotenv import load_dotenv
import os
import requests
import json

load_dotenv()
jwt = os.getenv("JWT")

API_URL = "https://caas.api.godaddy.com/v1/prompts"

preProcess = True

with open("signatures.json", "r") as file:
    signatures = file.read()

with open("sample_signatures.json", "r") as file:
    sample_signatures = file.read()

with open("529.txt", "r") as file:
    php_and_yara = file.read()

if(preProcess):
    with open("process.txt", "r") as f:
        system_context = f.read()
else:
    with open("system_context.txt", "r") as file:
        system_context = file.read()


headers = {
    "Authorization": "sso-jwt " + jwt,
    "Accept": "application/json",
    "Content-Type": "application/json"
}


try:
    params = {
        "prompts": [
            {
                "from": "system",
                "content": [
                    {
                        "type": "text",
                        "value": system_context
                    }
                ]
            },
            {
                "from": "user",
                "content": [
                    {
                        "type": "text",
                        "value": php_and_yara
                    }
                ]
            }
        ],
        "isPrivate": True,
        "provider": "anthropic_chat",
        "providerOptions": 
        { 
            "model": "claude-3-5-haiku-20241022-v1:0" 
        }
    }

    response = requests.post(url=API_URL, headers=headers, json=params)
    assistant_content = response.json()
    assistant_content = assistant_content["data"]["value"]["content"]
    print(assistant_content)

    
    with open("converted_yara.json", "w") as file:
        file.write(json.dumps(assistant_content, indent=4))  # convert dict → JSON string
    
    


except Exception as e:
    print(e)

