import os, sys
sys.path.append("..")
import src.client.safemsgclient as smc
from functools import (
        wraps
        )

def split_line(f):
    @wraps(f)
    def with_split_line(*args, **kwargs):
        print(f"*********************call {f.__name__}*****************")
        return f(*args, **kwargs)
    return with_split_line

def print_log(data):
    print(data)

@split_line
def test_create_keys():
    print_log(smc().create_keys(1024))

@split_line
def test_save_load_from_file():
    pri, pub = smc().create_keys()
    smc().save(pri, "prikey.rsa")
    print(f"save private key substring: {pri[len(pri)/4]}")
    print(f"save public key substring: {pub[len(pub)/4]}")
    smc().save(pub, "pubkey.rsa")
    lpri = smc().load_key("prikey.rsa")
    lpub = smc().load_key("pubkey.rsa")
    print(f"load private key substring: {lpri[len(lpri)/4]}")
    print(f"load public key substring: {lpub[len(lpub)/4]}")
    assert pri == lpri, f"load private key failed."
    assert pub == lpub, f"load public key failed."

@split_line
def test_generate_sign():
    pri, pub = smc().create_keys()
    message = "this is test generate sign and verify sign"
    print(f"private key: {pri}")
    print(f"public key: {pub}")
    print(f"test message: {message}")

    sign = smc().generate_sign(pri, message)
    print(f"sign message: {sign}")

    verify = smc().verify_sign(pub, sign)
    print(f"verify message state: {verify}")

@split_line
def test_encrypt_decrypt():
    pri, pub = smc().create_keys()
    message = "this is test encrypt and decrypt"
    print(f"test message: {message}")

    encrypt_msg = smc().encrypt(pub, message)
    print(f"encrypt message: {encrypt_msg}")

    decrypt_msg = smc().decrypt(pri, encrypt_msg)
    print(f"decrypt message: {decrypt_msg}")
    
    assert decrypt == message, f"encrypt/decrypt failed."
    


if __name__ == "__main__":
    test_create_keys()
