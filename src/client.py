import os
from src.crypto_client import (
        create_keys,
        save_file,
        load_key_from_file,
        generate_sign,
        verify_sign,
        encrypt,
        decrypt
        )

class safemsgclient(object):
    def __init__(self, *args, **kwargs):
        pass

    def create_keys(num = 2048, **kwargs):
        return create_keys(num)

    def save(key, filename, **kwargs):
        if filename:
            return save_file(filename)
        return False

    def load_key(filename, **kwargs):
        if filename:
            return load_key_from_file(filename)
        return None

    def verify_sign(pubkey, message, sign, secret = None, **kwargs):
        return verify_sign(pubkey, message, sign, secret)

    def generate_sign(privkey, unsign_message, secret = None, **kwargs): 
        return generate_sign(privkey, unsign_message, secret)

    def encrypt(pubkey, message, secret = None, **kwargs):
        return encrypt(pubkey, message, secrete):

    def decrypt(privkey, encrypt_message, secret = None, sentinel = None, **kwargs):
        return decrypt(privkey, encrypt_message, secret, sentinel):

    def __getatter__(self, name):
        return safemsgclient()

    def __call__(self, *args, **kwargs):
        pass
