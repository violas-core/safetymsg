import os
import base64
# °²×°pycrypto
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Signature import (
        PKCS1_v1_5 as Signature_pkcs1_v1_5
        )
from Crypto.PublicKey import (
        RSA
        )
from Crypto.Cipher import (
        PKCS1_v1_5 as Cipher_pkcs1_v1_5
        )
 
from functools import wraps


'''
  @dev create private key and public key
  @return (private_key, pubkey_key) base64.b64encode string

'''
def create_keys(num = 2048):
    if num % 1024 != 0 or num == 0:
        raise ValueError("input num is invalid. (1024  2048 ... num % 1024 == 0)")

    random_gen = Random.new().read
    rsa = RSA.generate(num, random_gen)
    pri = rsa.exportKey()
    pub = rsa.publickey().exportKey()
    return (base64.b64encode(pri), base64.b64encode(pub))

'''
  @dev save key(public private) to filename
  @param key will save key with key desc, format the same to create_keys's return, type = string(base64)
'''
def save_file(key, filename):
    with open(filename, 'wb') as pf:
        pf.write(base64.b64decode(key))
        return True
    return False

'''
  @dev load key(public private) from filename
  @param filename key file 
  @return key value typt = base64
'''
def load_key_from_file(filename):
    if not os.path.isfile(filename):
        raise ValueError(f"input filename({filename}) not found.")

    with open(doc) as pk:
        key= pk.read()
        return base64.b64encode(key)
    raise Exception(f"load key failed from {filename}")

'''
   @dev verify signature with pubkey
   @param pubkey public key use signature privkey
   @param message signature message, type = string(base64)
   @param secret rsa key secret, default None
   @return true : signature is ok false : not valid signature
'''
def verify_sign(pubkey, message, sign, secret = None):
    rsaKey = RSA.importKey(base64.b64decode(pubkey), passphrase=secret)
    verifier = Signature_pkcs1_v1_5.new(rsaKey)
    digest = SHA256.new()
    digest.update(message.encode('utf8'))
    is_verify = verifier.verify(digest, base64.b64decode(sign))
    return is_verify

'''
   @dev generate signature
   @param privkey private key
   @param unsign_message unsignature message, type = string
   @param secret rsa key secret, default None
   @return singnature message
'''
def generate_sign(privkey, unsign_message, secret = None):
    rsaKey = RSA.importKey(base64.b64decode(privkey), passphrase=secret)
    signer = Signature_pkcs1_v1_5.new(rsaKey)
    digest = SHA256.new()
    digest.update(unsign_message.encode('utf8'))
    sign = signer.sign(digest)
    signature = base64.b64encode(sign)
    return signature

'''
   @dev encrypt message with pubkey 
   @param pubkey encrypt privkey public key 
   @param message encrypt message, type = string
   @param secret rsa key secret, default None
   @return true : signature is ok false : not valid signature
'''
def encrypt(pubkey, message, secret = None):
    rsaKey = RSA.importKey(base64.b64decode(pubkey), passphrase=secret)
    cipher = Cipher_pkcs1_v1_5.new(rsaKey)
    encrypt_message = cipher.encrypt(bytes(message.encode("utf8")))

    return base64.b64encode(encrypt_message)

'''
   @dev decrypt message
   @param privkey private key
   @param encrypt_message decrypt message, type = string(base64)
   @param secret rsa key secret, default None
   @return message
'''
def decrypt(privkey, encrypt_message, secret = None, sentinel = None):
    rsaKey = RSA.importKey(base64.b64decode(privkey), passphrase=secret)
    cipher = Cipher_pkcs1_v1_5.new(rsaKey)
    return cipher.decrypt(base64.b64decode(encrypt_message), sentinel)


