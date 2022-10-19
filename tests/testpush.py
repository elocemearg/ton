#!/usr/bin/python3

import sys
import os
import subprocess
import tempfile

import testcommon

def create_file(containing_dir, file_def, byte_generator=None):
    if byte_generator is None:
        byte_generator = testcommon.DeterministicByteGenerator()
    else:
        byte_generator.reset()
    basename = file_def["name"]
    contents = file_def.get("contents", None)
    length = file_def.get("length", 0)

    path = os.path.join(containing_dir, basename)
    if contents is None or type(contents) == bytes:
        file_mode = "wb"
    else:
        file_mode = "w"
    with open(path, file_mode) as f:
        if contents is not None:
            # The definition requires this file to have specific contents.
            f.write(contents)
        else:
            # The definition requires this file to be a certain length of
            # deterministically pseudorandom rubbish.
            for i in range(0, length, 256):
                if i + 256 > length:
                    chunk_length = length - i
                else:
                    chunk_length = 256
                chunk = byte_generator.randbytes(chunk_length)
                f.write(chunk)

def create_file_set_def(containing_dir, file_set_entries, byte_generator):
    for entry in file_set_entries:
        name = entry["name"]
        if entry["type"] == "dir":
            new_dir = os.path.join(containing_dir, name)
            os.mkdir(new_dir)
            sub_entries = entry.get("entries", [])
            create_file_set_def(new_dir, sub_entries, byte_generator)
        elif entry["type"] == "file":
            create_file(containing_dir, entry)

def main():
    byte_generator = testcommon.DeterministicByteGenerator()
    ton_path = os.path.join(os.path.dirname(__file__), "..", "ton")
    num_tests = len(testcommon.test_defs)
    test_num = 1
    for test_def in testcommon.test_defs:
        test_name = test_def["name"]
        push_args = test_def["push_args"]
        file_set_name = test_def["file_set"]
        file_set_def = testcommon.file_set_defs[file_set_name]
        print("PUSH: [%d/%d] test %s..." % (test_num, num_tests, test_name))
        with tempfile.TemporaryDirectory(prefix="tontest_push_" + test_name) as temp_dir_name:
            passphrase = "passphrase " + test_name

            # Create our directory and file structure for this test
            create_file_set_def(temp_dir_name, file_set_def["entries"], byte_generator)

            # Name each dir or file in temp_dir_name on the command line
            top_level_entries = [ entry["name"] for entry in file_set_def["entries"] ]

            # Build the command line which consists of:
            # ton push [test-specific args] --passphrase <passphrase> -t 30
            # The passphrase is derived from the test name and testpull.py
            # derives the same passphrase. The timeout is so that if
            # testpull.py fails we'll eventually exit.
            command = [ ton_path, "push" ]
            command += push_args
            command += [ "--passphrase", passphrase, "-t", "30"]
            command += [ os.path.join(temp_dir_name, name) for name in top_level_entries ]
            subprocess.run(command, check=True)
        print("PUSH: [%d/%d] test %s passed." % (test_num, num_tests, test_name))
        test_num += 1
    sys.exit(0)

if __name__ == "__main__":
    main()
