#!/usr/bin/env python

with open("wonderful-hashes.txt", "rb") as f:
    for line in f:
        user, hash = line.rstrip().split(":")
        stuff = hash.split("$")
        modes = stuff[3]

        skip = False

        for mode in modes.split(","):
            mode = int(mode)
            # skip "expensive" hashes
            if mode in set([6, 7]):
                skip = True
                break
            if (mode - 10) in set([0, 6, 7]):
                skip = True
                break
            if (mode - 20) in range(0, 10):  # "local_salt" stuff
                skip = True
                break

        if not skip:
            print line.rstrip()
