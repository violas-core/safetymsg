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
        del_secret as azure_del_secret, 
        get_secrets_keys as azure_get_secrets_keys,
        get_deleted_secret as azure_get_deleted_secret,
        purge_deleted_secret as azure_purge_deleted_secret,
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

    def name_to_str(self, name):
        return name if isinstance(name, str) else name.value

    def add(self, name):
        name = self.name_to_str(name)
        setattr(self, name, self.secret(name))

    def get(self, name):
        name = self.name_to_str(name)
        return getattr(self, name)

    def set(self, name, key_vault_name, key_name, key_value = ""):
        secret = self.get(name)
        assert secret, f"not found secret({name})"

        secret.key_vault_name = key_vault_name
        secret.key_name = key_name
        secret.key_value = key_value

    def is_exists(self, name):
        name = self.name_to_str(name)

        return name in self.names

    def __getatter__(self, name):
        if name == self.secret.ATTER_NAMES.ITEMS.value:
            return [getattr(self, name) for name in self.names]
        elif name == self.secret.ATTER_NAMES.NAMES.value:
            return self.names

class safemsgclient(object):

    key_memory_id = "memory_id"
    key_head_flag = "memkey_"
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
    
    class key_source(autoname):
        FILE            = auto()
        KEY_VAULT       = auto()
        MEMORY          = auto()

    def __init__(self, key_source = key_source.FILE, azure_names = azure_names, use_mempool = True, *args, **kwargs):
        self.set_key_source(key_source)
        setattr(self, "use_mempool", use_mempool)
        self.__mempool_secrets = {}
        if key_source == key_source.KEY_VAULT:
            self.__init_azure_env_id()
            self.__init_azure_key_value_name(azure_names)
        pass

    def clear_mempool_secrets(self):
        self.__mempool_secrets = {}

    def use_mempool_secret(self):
        self.use_mempool = True

    def unuse_mempool_secret(self):
        self.use_mempool = False

    def __init_azure_env_id(self):
        for item in eaen:
            setattr(self, item.name, item)

    def __init_azure_key_value_name(self, azure_names = azure_names):
        setattr(self, "azure_key_vault", azure_key_vault([item.value for item in self.azure_names]))

    def create_keys(self, num = 2048, **kwargs):
        return create_keys(num)

    def save(self, key, filename, **kwargs):
        if filename:
            return save_file(key, filename)
        return False

    def load_key(self, filename, **kwargs):
        secret = None
        if filename:
            if self.use_mempool:
                secret = self.get_memory_key_value(filename)
            if not secret:
                secret = load_key_from_file(filename)
                self.set_memory_key_value(filename, secret)
            return secret
        return None

    def pre_azure_key(f):
        def use_azure(*args, **kwargs):
            self = args[0]
            args = list(args[1:])
            key_source = getattr(self, "key_source")

            key = None
            if args[0] and len(args[0]) > 0:
                key = args[0]
            elif key_source == self.key_source.MEMORY:
                memory_id = kwargs.get(self.key_memory_id)
                key = self.get_memory_key_value(memory_id)
            elif key_source == self.key_source.FILE:
                filename = kwargs.get("filename")
                key = self.load_key(filename)
            elif key_source == self.key_source.KEY_VAULT:
                azure_name = kwargs.get("azure_name")
                key_vault = self.azure_key_vault.get(azure_name)
                key = self.get_azure_secret_value(key_vault.key_vault_name, key_vault.key_name)

            args[0] = key
            
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

    ''' set azure env value
    '''
    def set_azure_client_id(self, id):
        self.AZURE_CLIENT_ID.env = id

    def set_azure_tenant_id(self, id):
        self.AZURE_TENANT_ID.env = id

    def set_azure_client_secret(self, secret):
        self.AZURE_CLIENT_SECRET.env = secret
    
    def set_azure_secret_ids(self, client_id, tenant_id, secret):
        self.set_azure_client_id(client_id)
        self.set_azure_tenant_id(tenant_id)
        self.set_azure_client_secret(secret)

    def get_azure_envs(self):
        '''
            @dev show all environ info of azure
            @return all environ info for azure
        '''
        return {item.name : getattr(self, item.name).env for item in eaen}

    '''
       azure key vault operate, must connect azure with azure cli or environ id
       connect to azure:
            case 1： az login -u USERNAME -p PASSWORD
            case 2:  use set_azure_secret_ids to set environ id
       CRUD operate: get_azure_secret, set_azure_secret, del_azure_secret
    '''
    def get_azure_secret(self, vault_name, key_name, version = None, **kwargs):
        '''
        @dev get secret from azure key vault
        @param vault_name key vault name
        @param key_name sercrt's key 
        @param version version of the secret to get. if unspecified, gets the latest version
        @return secret(KeyVaultSecret) 
        '''
        secret = None
        key = self.create_memory_key_with_args(vault_name, key_name, version)
        if self.use_mempool:
            secret = self.get_memory_key_value(key)
            if not secret:
                secret = azure_get_secret(vault_name, key_name, version, **kwargs)
        else:
            secret = azure_get_secret(vault_name, key_name, version, **kwargs)

        self.set_memory_key_value(key, secret)
        return secret

    def get_azure_secret_value(self, vault_name, key_name, version = None, **kwargs):
        '''
        @dev get secret from azure key vault
        @param vault_name name of key vault 
        @param key_name the name of secret 
        @param key_value the value of secret
        @return value of secret(KeyVaultSecret) 
        '''
        secret = None
        key = self.create_memory_key_with_args(vault_name, key_name, version, "value")
        if self.use_mempool:
            secret = self.get_memory_key_value(key)
            if not secret:
                secret = azure_get_secret(vault_name, key_name, version, **kwargs).value
        else:
            secret = azure_get_secret(vault_name, key_name, version, **kwargs).value

        self.set_memory_key_value(key, secret)
        return secret

    def set_azure_secret(self, vault_name, key_name, key_value, **kwargs):
        '''
        @def set a secret value. If name is in use, create a new version of the secret. If not, create a new secret.
        @param vault_name name of key vault 
        @param key_name the name of secret 
        @param key_value the value of secret
        @param kwargs 
            enabled (bool) – Whether the secret is enabled for use.
            tags (dict[str, str]) – Application specific metadata in the form of key-value pairs.
            content_type (str) – An arbitrary string indicating the type of the secret, e.g. ‘password’
            not_before (datetime) – Not before date of the secret in UTC
            expires_on (datetime) – Expiry date of the secret in UTC
        @return KeyVaultSecret
        '''
        
        ret = azure_set_secret(vault_name, key_name, key_value, **kwargs)
        self.del_memory_value(self.create_memory_key_with_args(vault_name, key_name))
        return ret

    def del_azure_secret(self, vault_name, key_name, **kwargs):
        self.del_memory_value(self.create_memory_key_with_args(vault_name, key_name))
        return azure_del_secret(vault_name, key_name, **kwargs)

    def get_azure_deleted_secret(self, vault_name, key_name, **kwargs):
        '''
        @dev get secret from azure key vault
        @param vault_name key vault name
        @param key_name sercrt's key 
        @return secret(DeletedSecret) 
        '''
        return azure_get_deleted_secret(vault_name, key_name, **kwargs)

    def get_azure_deleted_secret_id(self, vault_name, key_name, **kwargs):
        '''
        @dev get secret from azure key vault
        @param vault_name key vault name
        @param key_name sercrt's key 
        @return id of secret(DeletedSecret) 
        '''
        return self.get_azure_deleted_secret(vault_name, key_name, **kwargs).id

    def purge_deleted_secret(self, vault_name, key_name, **kwargs):
        '''
        @dev purge deleted secret from azure key vault
        @param vault_name key vault name
        @param key_name sercrt's key 
        '''
        return azure_purge_deleted_secret(self, vault_name, key_name, **kwargs)

    def set_azure_key_path(self, azure_name , key_vault_name, key_name):
        if not self.azure_key_vault.is_exists(azure_name):
            self.azure_key_vault.add(azure_name)

        return self.azure_key_vault.set(azure_name, key_vault_name, key_name)

    def get_azure_secrets_keys(self, vault_name):
        return azure_get_secrets_keys(vault_name)

    def create_memory_key(self, name):
        if name.startswith(self.key_head_flag):
            return name
        return self.make_md5(f"{self.key_head_flag}_{name}")

    def create_memory_key_with_args(self, *args):
        name = '_'.join([str(arg) for arg in args])
        return self.create_memory_key(name)

    def set_key_source(self, key_source = key_source.MEMORY):
        setattr(self, "key_source", key_source)

    def set_memory_key_value(self, name, value):
        return self.__mempool_secrets.update({self.create_memory_key(name): value})

    def get_memory_key_value(self, name):
        return self.__mempool_secrets.get(self.create_memory_key(name), None)

    def del_memory_value(self, key_start):
        for key in self.__mempool_secrets:
            if key.startswith(key_start):
                self.__mempool_secrets[key] = None
            

    def __getatter__(self, name):
        if getattr(self, name):
            return getattr(self, name)

        return safemsgclient()


    def __call__(self, *args, **kwargs):
        pass

