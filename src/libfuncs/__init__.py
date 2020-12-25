import os, sys
sys.path.append("..")
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../"))

import libfuncs
import libfuncs.comm_funcs


print_log = libfuncs.comm_funcs.print_log
split_line = libfuncs.comm_funcs.split_line
str_to_bytes = libfuncs.comm_funcs.str_to_bytes
bytes_to_str = libfuncs.comm_funcs.bytes_to_str

__all__ = [
        "print_log",
        "split_line",
        "str_to_bytes",
        "bytes_to_str"
        ]
