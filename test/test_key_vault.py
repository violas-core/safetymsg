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
    verify_msg = client.verify_sign(None, message, sign_msg, None, azure_name = smc.azure_names.VERIFY_KEY)
    assert verify_msg, f"sign/verify failed."

    print_log(f"message: {message}")
    print_log(f"sign message: {sign_msg}")
    print_log(f"verify message: {verify_msg}")

def test_sign_verify_with_key_vault_use_mempool():
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
    verify_msg = client.verify_sign(None, message, sign_msg, None, azure_name = smc.azure_names.VERIFY_KEY)
    assert verify_msg, f"sign/verify failed."

    message = "this is test sign and verify with key vault"
    sign_msg = client.generate_sign(None, message, None, azure_name = smc.azure_names.SIGN_KEY)
    verify_msg = client.verify_sign(None, message, sign_msg, None, azure_name = smc.azure_names.VERIFY_KEY)
    assert verify_msg, f"sign/verify failed."

    message = "this is test sign and verify with key vault"
    sign_msg = client.generate_sign(None, message, None, azure_name = smc.azure_names.SIGN_KEY)
    verify_msg = client.verify_sign(None, message, sign_msg, None, azure_name = smc.azure_names.VERIFY_KEY)
    assert verify_msg, f"sign/verify failed."

    print_log(f"message: {message}")
    print_log(f"sign message: {sign_msg}")
    print_log(f"verify message: {verify_msg}")

def save_datas(datas, filename):
    with open(filename, 'w') as pf:
        pf.write(datas.encode().hex())
        return True
    return False

def load_datas(filename):
    with open(filename, 'r') as pf:
        datas = pf.read()
    return bytes.fromhex(datas).decode()

def __input_ids(debug = True):
    if debug:
        client_id = "80f16cbd-e549-4c93-9e7b-22a91c8615d4"
        tenant_id = "d99eee11-8587-4c34-9201-38d5247df9c9"
        secret = "sUN0g~V9o81.M5UP1tJHKRMgxS_ru7g~O~"

    else:
        client_id = input(f"input azure_client_id: ")
        tenant_id = input(f"input azure_tenant_id: ")
        secret    = input(f"input azure_client_secret: ")
    return (client_id, tenant_id, secret)

def test_sign_verify_use_local_key_connect_azure():
    pri_filename = "private.key"
    pub_filename = "public.key"
    vault_name = "vault-test02"
    sign_name = "bvweb-sign-key"
    verify_name = "bvweb-verify-key"

    #create sign and verify key and save to file
    pri_key, pub_key = pri_pub()
    save_datas(pri_key, pri_filename)
    save_datas(pub_key, pub_filename)

    #load encrypt and decrypt from file
    decrypt_key = load_datas(pri_filename)
    encrypt_key = load_datas(pub_filename)

    #init client with key source KEY_VAULT
    client = smc(smc.key_source.KEY_VAULT, use_mempool = True)

    #encrypt key vault id(AZURE_CLIENT_ID, AZURE_TENANT_ID  AZURE_CLIENT_SECRET) and save to local file
    client_id , tenant_id, secret = __input_ids()
    client.save_azure_secret_ids_to_file("azure_ids.key", pub_key, client_id, tenant_id, secret)

    #set use sing and verify key(key vault) path
    client.set_azure_key_path(smc.azure_names.SIGN_KEY, vault_name, sign_name)
    client.set_azure_key_path(smc.azure_names.VERIFY_KEY, vault_name, verify_name)

    #use saved ids login key vault, first decrypt azure_ids.key , use decrypt_key
    client.set_azure_secret_ids_with_file("azure_ids.key", decrypt_key)


    message = "7b227374617465223a202253554343454544222c20226d657373616765223a2022222c20226461746173223a205b7b2261646472657373223a20223030303030303030303030303030303030303432353234373264343235343433222c202274797065223a20227632626d222c2022636861696e223a202276696f6c6173222c2022636f6465223a2022222c202266726f6d5f746f5f746f6b656e223a205b7b2266726f6d5f636f696e223a202276425443222c2022746f5f636f696e223a2022425443227d5d7d2c207b2261646472657373223a2022324e325961735455644c625873616648486d796f4b5559635252696352506755794e42222c202274797065223a20226232766d222c2022636861696e223a2022627463222c2022636f6465223a2022307833303030222c202266726f6d5f746f5f746f6b656e223a205b7b2266726f6d5f636f696e223a2022425443222c2022746f5f636f696e223a202276425443227d5d7d2c207b2261646472657373223a2022307846466636343538613037624362363964663245614562626639436634363361423038463366333942222c202274797065223a20226532766d222c2022636861696e223a2022657468657265756d222c2022636f6465223a2022222c202266726f6d5f746f5f746f6b656e223a205b7b2266726f6d5f636f696e223a202275736474222c2022746f5f636f696e223a20227655534454227d5d7d2c207b2261646472657373223a20223030303030303030303030303030303030303432353234373535353334343534222c202274797065223a20227632656d222c2022636861696e223a202276696f6c6173222c2022636f6465223a2022222c202266726f6d5f746f5f746f6b656e223a205b7b2266726f6d5f636f696e223a20227655534454222c2022746f5f636f696e223a202275736474227d5d7d5d7d"
    target_sign_msg = "WqscO4Ybe7cbN98LVa/mifP96k5qr6ZxjgoRte2G0gY2QB5E2zwtnctHj501QZQ1eBhPZb6pPKfJdqWE80e9vvd9QV2U1MBXITZk1vn6J7AG72fPuGhxE/SLAO8GDcWeJKTh8qHvVAb0onJ/brxsRS1BhnI7FNOYZSATpLb38iudWQBJmKAChaTNiNduf5x0CEutp/SAHK1hvARjpTj5fI8AeLt2a7vQsp4+vBpvW5IuvyaEsG4bC/rMlxnZRERZGTje9lVHAHsrb2x4U1vZM4UrCtF1gmIIgY27S3kAdgnO6mf8vvXR8lf0BL29rJPV1mK2nhq5mJkQbppbTuye5Q=="

    #sign message
    sign_msg        = client.generate_sign(None, message, None, azure_name = smc.azure_names.SIGN_KEY)
    assert target_sign_msg == sign_msg, f"sing_msg is error"

    #verify sign
    verify_state    = client.verify_sign(None, message, sign_msg, None, azure_name = smc.azure_names.VERIFY_KEY)
    assert verify_state, f"sign/verify failed."
