import os, sys
import unittest

sys.path.append("..")
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../"))
from src import *
from functools import (
     wraps
        )


def cut_key(key):
    return smc().make_md5(key)

def pri_pub():
    return smc().create_keys()

@split_line
def test_create_keys():
    '''test create keys'''
    pri, pub = pri_pub()
    print_log(f"private key md5: {cut_key(pri)}")
    print_log(f"public key md5: {cut_key(pub)}")

def test_save_load_from_file():
    """test_save_load_from_file"""
    pri, pub = pri_pub()
    print_log(f"save private key md5: {cut_key(pri)}")
    print_log(f"save public key md5: {cut_key(pub)}")
    smc().save(pri, "prikey.rsa")
    smc().save(pub, "pubkey.rsa")

    lpri = smc().load_key("prikey.rsa")
    lpub = smc().load_key("pubkey.rsa")
    print_log(f"load private key md5: {cut_key(pri)}")
    print_log(f"load public key md5: {cut_key(pub)}")

    assert pri == lpri, f"load private key failed."
    assert pub == lpub, f"load public key failed."

@split_line
def test_generate_sign():
    pri, pub = pri_pub()
    message = "this is test generate sign and verify sign"
    print_log(f"private key: {cut_key(pri)}")
    print_log(f"public key: {cut_key(pub)}")
    print_log(f"test message: {message}")

    sign = smc().generate_sign(pri, message)
    print_log(f"sign message: {sign}")

    verify = smc().verify_sign(pub, message, sign)
    print_log(f"verify sign: {verify}")
    assert verify

@split_line
def test_encrypt_decrypt():
    pri, pub = pri_pub()
    message = "this is test encrypt and decrypt"
    print_log(f"test message: {message}")

    encrypt_msg = smc().encrypt(pub, message, None)
    print_log(f"encrypt message: {encrypt_msg}")

    decrypt_msg = smc().decrypt(pri, encrypt_msg)
    print_log(f"decrypt message: {decrypt_msg}")
    
    assert decrypt_msg == message, f"encrypt/decrypt failed."


@split_line
def test_encrypt_decrypt_from_file():
    pubfile = "encryptkey.rsa"
    privfile = "decryptkey.rsa"
    if not os.path.exists(pubfile) or not os.path.exists(privfile):
        pri, pub = pri_pub()
        smc().save(pub, pubfile)
        smc().save(pri, privfile)

    message = "this is test encrypt and decrypt"
    print_log(f"test message: {message}")

    encrypt_msg = smc().encrypt(None, message, filename=pubfile)
    print_log(f"encrypt message: {encrypt_msg}")

    decrypt_msg = smc().decrypt(None, encrypt_msg, filename = privfile)
    print_log(f"decrypt message: {decrypt_msg}")
    
    assert decrypt_msg == message, f"encrypt/decrypt failed."


if __name__ == "__main__":
    unittest.main()
