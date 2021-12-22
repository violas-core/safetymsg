import os, sys, json
import requests
import urllib.request
from urllib.parse import urlparse
import time

sys.path.append("..")
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../"))

from functools import (
     wraps
        )

from src import *
def cut_key(key):
    return smc().make_md5(key)

def pri_pub():
    pri, pub = smc().create_keys()
    print('pri:\n {}'.format(pri))
    print('pub:\n {}'.format(pub))

    return (pri, pub)

requests.adapters.DEFAULT_RETRIES = 10
s = requests.session()
def send_request(url, body):
    headers = {"Content-Type": "application/json"}

    ret = requests.post(url, data = json.dumps(body), headers = headers)
    if ret.status_code == requests.codes.ok:
        sc      = ret.status_code
        ct      = ret.headers.get("Content-Type")
        data    = json.loads(ret.text) if ret.text else None
        print(data)
    else:
        print(ret)

def sign():
    client = smc()
    pri = client.load_key_from_file("/home/yzq/work/safetymsg/access.key")
    times = int(time.time() * 1000)
    msg = "tYaAh94iPTUNFWRW{}".format(times)
    msg = client.generate_sign_hex(pri, msg)
    body = {
            "accessId": "tYaAh94iPTUNFWRW",
            "time": str(times),
            "secret": msg
            }
    print(msg)

    send_request("https://rest.baas.alipay.com/api/contract/shakeHand", body)

sign()
