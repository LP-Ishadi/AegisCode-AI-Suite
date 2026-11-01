import os
import pickle
import subprocess

import jwt
import requests
import yaml
from flask import Flask


def insecure(request, payload):
    eval(payload)
    exec(payload)
    pickle.loads(payload)
    yaml.load(payload, Loader=yaml.UnsafeLoader)
    subprocess.run("echo hello", shell=True)
    requests.get("https://example.com", verify=False)
    jwt.decode(payload, options={"verify_signature": False})
    app = Flask(__name__)
    app.run(debug=True)
    command = request.args.get("command")
    os.system(command)
