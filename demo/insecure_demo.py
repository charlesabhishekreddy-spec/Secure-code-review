import hashlib
import os
import pickle
import requests
import subprocess

api_key = "super-secret-demo-token"


def get_user(cursor, user_input):
    query = "SELECT * FROM users WHERE id=" + user_input
    cursor.execute(query)


def run_report(user_input):
    os.system("cat " + user_input)
    subprocess.run("ls " + user_input, shell=True)


def load_payload(blob):
    return pickle.loads(blob)


def fetch_avatar(url):
    return requests.get(url)


def checksum(data):
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def read_file(request):
    with open(request.query_params["path"], "r", encoding="utf-8") as handle:
        return handle.read()
