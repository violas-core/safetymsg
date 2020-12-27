import os, sys
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
    return smc().create_keys()

def __get_ids():
    client_id = "80f16cbd-e549-4c93-9e7b-22a91c8615d4"
    tenant_id = "d99eee11-8587-4c34-9201-38d5247df9c9"
    secret = "sUN0g~V9o81.M5UP1tJHKRMgxS_ru7g~O~"
    return (client_id, tenant_id, secret)

def test_get_secret_from_azure():
    client = smc(key_source.KEY_VAULT)
    client_id, tenant_id, secret = __get_ids()
    client.set_azure_secret_ids( client_id, tenant_id, secret)

    vault_name = "vault-test02"
    key_names = client.get_azure_secrets_keys(vault_name)
    print_log(f"{vault_name} keys: {key_names}")

    for key_name in key_names:
        print_log(f"{vault_name}.{key_name} value: {client.get_azure_secret_value(vault_name, key_name)}")

def test_set_secret_to_azure():
    client = smc(key_source.KEY_VAULT)
    client_id , tenant_id, secret = __get_ids()
    client.set_azure_secret_ids( client_id, tenant_id, secret)
    vault_name = "vault-test02"
    pri_key, pub_key = pri_pub()
    key_pri_name = "pri-set-key"
    key_pub_name = "pub-set-key"

    client.set_azure_secret(vault_name, key_pri_name, pri_key)
    client.set_azure_secret(vault_name, key_pub_name, pub_key)

    ret_pri_key = client.get_azure_secret_value(vault_name, key_pri_name)
    assert pri_key == ret_pri_key, f"get {key_pri_name} failed. pri_key != ret_pri_key"

    
    ret_pub_key = client.get_azure_secret_value(vault_name, key_pub_name)
    assert pub_key == ret_pub_key, f"get {key_pub_name} failed. pub_key != ret_pub_key"

def test_del_secret_to_azure():
    client = smc(key_source.KEY_VAULT)
    client_id , tenant_id, secret = __get_ids()
    client.set_azure_secret_ids( client_id, tenant_id, secret)
    vault_name = "vault-test02"
    key_del_name = f"key-del-test-{int(time.time())}"
    key_del_value = f"this is test del at {key_del_name}"

    print_log(f"test del {key_del_name} : {key_del_value}")
    client.set_azure_secret(vault_name, key_del_name, key_del_value)

    client.del_azure_secret(vault_name, key_del_name)

    
    id = client.get_azure_deleted_secret_id(vault_name, key_del_name)
    assert id, f"get {key_del_name} failed"

def test_encrypt_decrypt_with_key_vault():
    client = smc(smc.key_source.KEY_VAULT)
    client_id , tenant_id, secret = __get_ids()
    client.set_azure_secret_ids( client_id, tenant_id, secret)
    vault_name = "vault-test02"
    pri_key, pub_key = pri_pub()
    key_pri_name = "encrypt-key"
    key_pub_name = "decrypt-key"

    client.set_azure_secret(vault_name, key_pri_name, pri_key)
    client.set_azure_secret(vault_name, key_pub_name, pub_key)

    client.set_azure_key_path(smc.azure_names.ENCRYPT_KEY, vault_name, key_pub_name)
    client.set_azure_key_path(smc.azure_names.DECRYPT_KEY, vault_name, key_pri_name)

    message = "this is test encrypt and decrypt with key vault"
    encrypt_msg = client.encrypt(None, message, None, azure_name = smc.azure_names.ENCRYPT_KEY)
    decrypt_msg = client.decrypt(None, encrypt_msg, None, azure_name = smc.azure_names.DECRYPT_KEY)
    assert decrypt_msg == message, f"encrypt/decrypt failed."

    print_log(f"message: {message}")
    print_log(f"encrypt message: {encrypt_msg}")
    print_log(f"decrypt message: {decrypt_msg}")

def test_sign_verify_with_key_vault():
    client = smc(smc.key_source.KEY_VAULT)
    client_id , tenant_id, secret = __get_ids()
    client.set_azure_secret_ids( client_id, tenant_id, secret)
    vault_name = "vault-test02"
    pri_key, pub_key = pri_pub()
    sign_name = "sign-key"
    verify_name = "verify-key"

    client.set_azure_secret(vault_name, sign_name, pri_key)
    client.set_azure_secret(vault_name, verify_name, pub_key)

    client.set_azure_key_path(smc.azure_names.SIGN_KEY, vault_name, sign_name)
    client.set_azure_key_path(smc.azure_names.VERIFY_KEY, vault_name, verify_name)

    message = "this is test sign and verify with key vault"
    sign_msg = client.generate_sign(None, message, None, azure_name = smc.azure_names.SIGN_KEY)
    verify_msg = client.verify_sign(None, encrypt_msg, None, azure_name = smc.azure_names.VERIFY_KEY)
    assert verify_msg == message, f"sign/verify failed."

    print_log(f"message: {message}")
    print_log(f"sign message: {sign_msg}")
    print_log(f"verify message: {verify_msg}")
