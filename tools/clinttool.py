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
