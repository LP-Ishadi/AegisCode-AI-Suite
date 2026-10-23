import json
import subprocess

import jwt
import requests
import yaml


def safer(payload, key):
    json.loads(payload)
    yaml.safe_load(payload)
    subprocess.run(["echo", payload], shell=False)
    requests.get("https://example.com", verify=True)
    jwt.decode(payload, key, algorithms=["HS256"])
