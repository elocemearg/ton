#!/usr/bin/python3

import sys
import os
import subprocess
import tempfile

import testcommon

class FileSetMismatchException(Exception):
    pass

class FileSetContentsMismatchException(Exception):
    pass

def check_file_contents(path, expected_contents):
    with open(path, "rb") as f:
        observed_contents = f.read().decode("utf-8")
        if expected_contents != observed_contents:
            raise FileSetContentsMismatchException("%s: expected contents:\n%s\tobserved contents:\n%s" % (path, expected_contents, observed_contents))

def check_file_pseudorandom_contents(path, expected_length, byte_generator):
    byte_generator.reset()
    with open(path, "rb") as f:
        bytes_read = 0
        length = 1
        while length > 0:
            chunk = f.read(1000)
            length = len(chunk)
            if length > 0:
                expected_chunk = byte_generator.randbytes(length)
                for i in range(length):
                    if expected_chunk[i] != chunk[i]:
                        raise FileSetContentsMismatchException("%s: position %d: incorrect byte: expected 0x%02x, observed 0x%02x" % (path, bytes_read + i, int(expected_chunk[i]), int(chunk[i])))
                bytes_read += length

def check_against_file_set_def(path, entries, byte_generator):
    # Ensure the list of files/dirs in "path", sorted alphabetically, is
    # identical to the names of entries in "entries", sorted alphabetically.
    path_entries = sorted(os.listdir(path))
    expected_entries = sorted([ entry["name"] for entry in entries ])

    for idx in range(len(expected_entries)):
        if idx >= len(path_entries):
            observed_name = None
        else:
            observed_name = path_entries[idx]
        expected_name = expected_entries[idx]
        if observed_name is None or observed_name > expected_name:
            raise FileSetMismatchException("%s: expected file %s not found" % (path, expected_name))
        elif observed_name < expected_name:
            raise FileSetMismatchException("%s: found unexpected file name %s" % (path, observed_name))

    # For each entry in "entries", if it's a file, check it contains the right
    # data, and if it's a directory, check it recursively.
    for entry in entries:
        entry_path = os.path.join(path, entry["name"])
        if entry["type"] == "file":
            if "contents" in entry:
                check_file_contents(entry_path, entry["contents"])
            else:
                check_file_pseudorandom_contents(entry_path, entry["length"], byte_generator)
        elif entry["type"] == "dir":
            check_against_file_set_def(entry_path, entry["entries"], byte_generator)

def main():
    byte_generator = testcommon.DeterministicByteGenerator()
    ton_path = os.path.join(os.path.dirname(__file__), "..", "ton")
    num_tests = len(testcommon.test_defs)
    test_num = 1
    for test_def in testcommon.test_defs:
        test_name = test_def["name"]
        pull_args = test_def["pull_args"]
        file_set_name = test_def["file_set"]
        file_set_def = testcommon.file_set_defs[file_set_name]
        print("PULL: [%d/%d] test %s..." % (test_num, num_tests, test_name))
        with tempfile.TemporaryDirectory(prefix="tontest_pull_" + test_name) as temp_dir_name:
            # Build our "ton pull" command, to receive the files and put them
            # in the directory temp_dir_name.
            passphrase = "passphrase " + test_name
            command = [ ton_path, "pull" ]
            command += pull_args
            command += [ "--passphrase", passphrase, "--max-announcements", "30" ]
            command += [ temp_dir_name ]
            subprocess.run(command, check=True)

            # Check that we got all the files, we didn't get any extra files,
            # and all the files we got have the right contents.
            check_against_file_set_def(temp_dir_name, file_set_def["entries"], byte_generator)
        print("PULL: [%d/%d] test %s passed." % (test_num, num_tests, test_name))
        test_num += 1
    sys.exit(0)

if __name__ == "__main__":
    main()
