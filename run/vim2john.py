#!/usr/bin/env python

# See https://dgl.cx/2014/10/vim-blowfish for details, and faster attacks.
#
# Based on https://github.com/xenocons/vim72bf/ code.
#
# This software is Copyright (c) 2014, Dhiru Kholia, and it is hereby released
# to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import sys
import struct
import os
from binascii import hexlify


CRYPT_MAGIC_LEN = 12
CRYPT_MAGIC_HEAD = "VimCrypt~"


def process_file(filename):

    f = open(filename, "rb")

    f.seek(-4, 2)

    # TODO

    if True:
        sys.stderr.write("Something went wrong - fread(salt) error\n")
        sys.exit(1)

    sys.stdout.write("%s:$keychain$*" % os.path.basename(filename))
    # sys.stdout.write(hexlify(salt).decode("ascii"))
    # sys.stdout.write("*")
    # sys.stdout.write(hexlify(iv).decode("ascii"))
    # sys.stdout.write("*")
    # sys.stdout.write(hexlify(ct).decode("ascii"))
    # sys.stdout.write("\n")

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s [Vim encrypted file(s)]\n", sys.argv[1])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
