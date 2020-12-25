import os, sys
from functools import (
        wraps
        )
sys.path.append("..")
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../"))

def print_log(data):
    print(f"{data}")
    pass

def split_line(f):
    @wraps(f)
    def with_split_line(*args, **kwargs):
        print_log(f"\n*********************call {f.__name__}*****************")
        return f(*args, **kwargs)
    return with_split_line

def str_to_bytes(data):
    return data.encode("utf8") if isinstance(data, str) else data

def bytes_to_str(data):
    return data.decode() if isinstance(data, bytes) else data
