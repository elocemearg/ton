#!/usr/bin/python3

import sys
import random

BYTE_GEN_DEFAULT_SEED = 12345

"""
file_set_defs: mapping of names to definitions.

Each definition represents a directory structure and the files in it.
Each definition contains an array called "entries", each element of which is
a directory entry or a file entry.

A directory entry ("type" : "dir") contains a "name" and another
"entries" array which contains the directory's entries.

A file entry ("type" : "file") contains a "name" and either an integer
"length" or a string "contents". "contents" specifies the string contents
of the file, otherwise "length" means the file is to contain a pseudorandom
sequence of this byte length.

A symlink entry ("type" : "symlink") contains a "name" and "target" and is
ignored on Windows.
"""

file_set_defs = {
    "random1" : {
        "entries" : [
            {
                "type" : "dir",
                "name" : "dir_1",
                "entries" : [
                    {
                        "type" : "dir",
                        "name" : "dir_1_1",
                        "entries" : [
                            {
                                "type" : "file",
                                "name" : "bigfile.bin",
                                "length" : 20000000
                            },
                            {
                                "type" : "file",
                                "name" : "emptyfile.bin",
                                "length" : 0
                            },
                            {
                                "type" : "dir",
                                "name" : "dir_1_1_1",
                                "entries" : [
                                    {
                                        "type" : "file",
                                        "name" : "foo.bin",
                                        "length" : 10000
                                    },
                                    {
                                        "type" : "file",
                                        "name" : "bar.bin",
                                        "length" : 10000
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "type" : "dir",
                        "name" : "dir_1_2",
                        "entries" : [
                            {
                                "type" : "file",
                                "name" : "??.txt",
                                "contents" : "??"
                            },
                        ]
                    }
                ]
            },
            {
                "type" : "dir",
                "name" : "dir_2",
                "entries" : [
                ]
            },
            {
                "type" : "dir",
                "name" : "emptydir",
                "entries" : [
                ]
            },
            {
                "type" : "file",
                "name" : "toplevelfile.bin",
                "length" : 1024
            },
            {
                "type" : "symlink",
                "name" : "??.link.txt",
                "target" : "dir_1/dir_1_2/??.txt"
            }
        ]
    },

    # Only one file, more for tests that test various network options rather
    # than whether the directory structure gets sent correctly.
    "onefile" : {
        "entries" : [
            {
                "type" : "file",
                "name" : "onefile.txt",
                "contents" : "The quick brown fox jumps over the lazy dog."
            }
        ]
    }
}


"""
test_defs: array of test definitions.

Each entry represents a test. Each test object contains the following keys:
    "name": the unique test name,
    "file_set": the name of one of the file set definitions in file_set_defs.
                The pushing side will create this directory structure and the
                pulling side will receive it and check it's correct.
    "push_args": extra arguments to "ton push" other than the path.
    "pull_args": extra arguments to "ton pull" other than the path.
"""

test_defs = [
    {
        "name" : "random1",
        "file_set" : "random1",
        "push_args" : [],
        "pull_args" : []
    },
    {
        "name" : "random2_ipv6",
        "file_set" : "onefile",
        "push_args" : [ "-6" ],
        "pull_args" : [],
    },
    {
        "name" : "random3_ipv4",
        "file_set" : "onefile",
        "push_args" : [],
        "pull_args" : [ "-4" ],
    },
    {
        "name" : "random4_full_metadata",
        "file_set" : "random1",
        "push_args" : [ "--send-full-metadata" ],
        "pull_args" : []
    },
    {
        "name" : "random5_set_discovery_port",
        "file_set" : "onefile",
        "push_args" : [ "--discover-port", "48576" ],
        "pull_args" : [ "--discover-port", "48576" ]
    },
    {
        "name" : "random6_multicast_only",
        "file_set" : "onefile",
        "push_args" : [],
        "pull_args" : [ "--multicast" ]
    },
    {
        "name" : "random7_broadcast_only",
        "file_set" : "onefile",
        "push_args" : [],
        "pull_args" : [ "--broadcast" ]
    }
]

def get_num_tests():
    return len(test_defs)

def get_test_name(num):
    if num < 0 or num >= len(test_defs):
        return None
    else:
        return test_defs[num]["name"]

def get_push_args(num):
    if num < 0 or num >= len(test_defs):
        return None
    else:
        return test_defs[num]["push_args"]

def get_pull_args(num):
    if num < 0 or num >= len(test_defs):
        return None
    else:
        return test_defs[num]["pull_args"]

class DeterministicByteGenerator(object):
    """
    DeterministicByteGenerator: acts as a source of pseudorandom bytes in a
    deterministic sequence, which repeats every self.sequence_length bytes.
    """

    def __init__(self):
        self.seed = BYTE_GEN_DEFAULT_SEED
        self.sequence_length = 10000
        rng = random.Random(self.seed)
        self.sequence = bytes([rng.randint(0, 255) for i in range(self.sequence_length)])
        self.reset()

    def reset(self):
        self.sequence_position = 0

    def randbytes(self, length):
        arr = bytearray([])
        bytes_written = 0
        while bytes_written < length:
            chunk_length = length - bytes_written
            if chunk_length > self.sequence_length - self.sequence_position:
                chunk_length = self.sequence_length - self.sequence_position
            arr += self.sequence[self.sequence_position:(self.sequence_position + chunk_length)]
            self.sequence_position += chunk_length
            assert(self.sequence_position <= self.sequence_length)
            if self.sequence_position == self.sequence_length:
                self.sequence_position = 0
            bytes_written += chunk_length
        return arr
