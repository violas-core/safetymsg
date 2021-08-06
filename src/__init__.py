import os, sys
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "./src"))
from .libfuncs import (
        split_line,
        print_log,
        str_to_bytes,
        bytes_to_str
        )

import client
safemsgclient = client.safemsgclient
key_source = client.safemsgclient.key_source
azure_names = client.safemsgclient.azure_names
smc = client.safemsgclient

__all__ = [
        "safemsgclient",
        "key_source",
        "azure_names",
        "split_line", 
        "print_log",
        "smc",
        "bytes_to_str",
        "str_to_bytes"
        ]
