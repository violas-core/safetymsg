import os, sys

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
        print_log(f"{vault_name}.{key_name} value: {client.get_azure_secret(vault_name, key_name)}")

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

    ret_pri_key = client.get_azure_secret(vault_name, key_pri_name)
    assert pri_key == ret_pri_key, f"get {key_pri_name} failed. pri_key != ret_pri_key"

    
    ret_pub_key = client.get_azure_secret(vault_name, key_pub_name)
    assert pub_key == ret_pub_key, f"get {key_pub_name} failed. pub_key != ret_pub_key"
