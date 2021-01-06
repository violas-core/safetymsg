import sys
import os
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "./"))
import src.client
smc_client = src.client.safemsgclient
smc_azure_names = smc_client.azure_names
smc_key_source = smc_client.key_source

__all__ = ["smc_client", "smc_azure_names", "smc_key_source"]
