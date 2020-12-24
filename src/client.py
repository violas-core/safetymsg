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

from src.azure_key_vault_client import (
        get_secret as azure_get_secret,
        set_secret as azure_set_secret,
        show_secrets as azure_show_secrets,
        azure_environ_name as eaen
        )
from functools import (
        wraps
        )

from enum import (
        Enum,
        auto
        )

class enumbase(Enum):
    @property
    def info(self):
        return f"{self.name}:{self.value}"

class autoname(enumbase):
    def _generate_next_value_(name, start, count, last_values):
        return name.lower()

class azure_key_vault(object):
    SPLIT_SYMBOL = ";"

    class secret(object):
        class ATTER_NAMES(autoname):
            NAME            = auto()
            NAMES           = auto()
            ITEMS           = auto()
            KEY_VAULT_NAME  = auto()
            KEY_NAME        = auto()
            KEY_VALUE       = auto()

        def __init__(self, name):
            [setattr(self, item.value, "") for item in self.ATTER_NAMES]
            self.name = name

    def __init__(self, names):
        if names and isinstance(names, str):
            names = names.split(self.SPLIT_SYMBOL)

        if not names:
            raise ValueError(f"input args({names}) is invalid.")

        setattr(self, self.secret.ATTER_NAMES.NAMES.value, set(names))
        for name in self.names:
            setattr(self, name, self.secret(name))

    def get(self, name):
        return getattr(self, name if isinstance(name, str) else name.value)

    def set(self, name, key_vault_name, key_name, key_value = ""):
        secret = self.get(name)
        assert secret, f"not found secret({name})"

        secret.key_vault_name = key_vault_name
        secret.key_name = key_name
        secret.key_value = key_value

    def __getatter__(self, name):
        if name == self.secret.ATTER_NAMES.ITEMS.value:
            return [getattr(self, name) for name in self.names]
        elif name == self.secret.ATTER_NAMES.NAMES.value:
            return self.names


class azure_names(autoname):
    '''
       SIGN_KEY: private key
       VERIFY_KEY: SIGN_KEY's public key 
       ENCRYPT_KEY: public key
       DECRYPT_KEY: ENCRYPT_KEY's public key
    '''
    SIGN_KEY        = auto()
    VERIFY_KEY      = auto()
    ENCRYPT_KEY     = auto()
    DECRYPT_KEY     = auto()

class safemsgclient(object):


    class key_source(autoname):
        FILE            = auto()
        KEY_VAULT       = auto()
        MEMORY          = auto()

    def __init__(self, key_source = key_source.FILE, *args, **kwargs):
        self.__init_azure_env_id()
        self.__init_azure_key_value_name()
        self.set_key_source(key_source)
        pass

    def __init_azure_env_id(self):
        for item in eaen:
            setattr(self, item.name, item)

    def __init_azure_key_value_name(self):
        setattr(self, "azure_key_vault", azure_key_vault([item.value for item in azure_names]))

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

    def pre_azure_key(f):
        #@wraps
        def use_azure(*args, **kwargs):
            self = args[0]
            args = list(args[1:])
            key_source = getattr(self, "key_source")

            key = self.get_memory_key_value(f.__name__)
            if args[0] and len(args[0]) > 0:
                key = args[0]
            elif key:
                pass
            elif key_source == self.key_source.MEMORY:
                key = self.get_memory_key_value(f.__name__)
            elif key_source == self.key_source.FILE:
                filename = kwargs.get("filename")
                print(f"filename: --- {filename}")
                key = self.load_key(filename)
                print(f"key:----{self.make_md5(key)}")
            elif key_source == self.key_source.KEY_VAULT:
                azure_name = kwargs.get("azure_key_vault")
                key_vault = self.azure_key_vault.get(azure_name)
                key = self.azure_get_secret(key_vault.key_vault_name, key_vault.key_name)

            args[0] = key
            
            self.set_memory_key_value(f.__name__, key)
            return f(self, *args, **kwargs)
        return use_azure

    @pre_azure_key
    def verify_sign(self, pubkey, message, sign, secret = None, **kwargs):
        return verify_sign(pubkey, message, sign, secret)

    @pre_azure_key
    def generate_sign(self, privkey, unsign_message, secret = None, **kwargs): 
        return generate_sign(privkey, unsign_message, secret)

    @pre_azure_key
    def encrypt(self, pubkey, message, secret = None, **kwargs):
        return encrypt(pubkey, message, secret)

    @pre_azure_key
    def decrypt(self, privkey, encrypt_message, secret = None, sentinel = None, **kwargs):
        return decrypt(privkey, encrypt_message, secret, sentinel)

    def make_md5(self, message):
        return make_md5(message)

    def set_azure_client_id(self, id):
        self.AZURE_CLIENT_ID.env = id

    def set_azure_tenant_id(self, id):
        self.AZURE_TENANT_ID.env = id

    def set_azure_client_secret(self, secret):
        self.AZURE_CLIENT_SECRET.env = secret
    
    def get_azure_envs(self):
        return {item.name : item.env for item in eaen}

    def get_secret(self, vault_name, key_name):
        return azure_get_secret(vault_name, key_name)

    def set_secret(self, vault_name, key_name, key_value):
        return azure_set_secret(vault_name, key_name, key_value)

    def set_key_path(self, azure_name : azure_names, key_vault_name, key_name):
        return self.pre_azure_key_vault.set(azure_name, key_vault_name, key_name)
    
    def create_memory_key(self, name):
        return f"memkey_{name}"

    def set_key_source(self, key_source = key_source.MEMORY):
        setattr(self, "key_source", key_source)

    def set_memory_key_value(self, name, value):
        return setattr(self, self.create_memory_key(name), value)

    def get_memory_key_value(self, name):
        return getattr(self, self.create_memory_key(name), None)

    def __getatter__(self, name):
        if getattr(self, name):
            return getattr(self, name)

        return safemsgclient()

    def __call__(self, *args, **kwargs):
        pass

