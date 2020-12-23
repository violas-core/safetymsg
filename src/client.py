import os
from src.crypto_client import (
        create_keys,
        save_file,
        load_key_from_file,
        generate_sign,
        verify_sign,
        encrypt,
        decrypt,
        make_md5
        )

class safemsgclient(object):
    def __init__(self, *args, **kwargs):
        pass

    def create_keys(self, num = 2048, **kwargs):
        return create_keys(num)

    def save(self, key, filename, **kwargs):
        if filename:
            return save_file(key, filename)
        return False

    def load_key(self, filename, **kwargs):
        if filename:
            return load_key_from_file(filename)
        return None

    def verify_sign(self, pubkey, message, sign, secret = None, **kwargs):
        return verify_sign(pubkey, message, sign, secret)

    def generate_sign(self, privkey, unsign_message, secret = None, **kwargs): 
        return generate_sign(privkey, unsign_message, secret)

    def encrypt(self, pubkey, message, secret = None, **kwargs):
        return encrypt(pubkey, message, secret)

    def decrypt(self, privkey, encrypt_message, secret = None, sentinel = None, **kwargs):
        return decrypt(privkey, encrypt_message, secret, sentinel)

    def make_md5(self, message):
        return make_md5(message)

    def __getatter__(self, name):
        return safemsgclient()

    def __call__(self, *args, **kwargs):
        pass
