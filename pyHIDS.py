#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""pyHIDS. Python HIDS implementation.

pyHIDS verify the integrity of your system.
pyHIDS can prevent the admin by mail, log file and syslog.
"""

"""
pyHIDS. Python HIDS. Security software.
pyHIDS verify the integrity of your system.
Copyright (C) 2010-2018 Cedric Bonhomme

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

pyHIDS Copyright (C) 2010-2018 Cedric Bonhomme
This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
This is free software, and you are welcome to redistribute it
under certain conditions; type `show c' for details.
"""

__author__ = "Cedric Bonhomme"
__version__ = "$Revision: 0.4 $"
__date__ = "$Date: 2010/03/06 $"
__revision__ = "$Date: 2014/01/07 $"
__copyright__ = "Copyright (c) 2010-2018 Cedric Bonhomme"
__license__ = "GPL v3"

import os
import time
import pickle
import hashlib
import threading, queue
import subprocess
import rsa
import hmac
import binascii
from contextlib import contextmanager
import conf
from genBase import update_base, search_files
from conf import scan_files

# lock object to protect the log file during the writing
lock = threading.Lock()
# lock object used when sending alerts via irc
irker_lock = threading.Lock()

Q = queue.Queue()


def load_base():
    """
    Load the base file.

    Return a dictionnary wich contains filenames
    and theirs hash value.
    """
    # try to open the saved base of hash values
    database = None
    with open(conf.DATABASE, "rb") as serialized_database:
        database = pickle.load(serialized_database)

    return database


def compare_hash(target_file, expected_hash, hash_alg, log_file):
    """
    Compare 2 hash values.

    Compare the hash value of the target file
    with the expected hash value.
    """
    opened_file = None

    # each log's line contain the local time. it makes research easier.
    local_time = time.strftime("[%d/%m/%y %H:%M:%S]", time.localtime())

    # test for safety. Normally expected_hash != "" thanks to genBase.py
    if expected_hash == "":
        globals()['warning'] = globals()['warning'] + 1
        log(log_file, local_time + " No hash value for " + target_file)

    # opening the file to test
    try:
        opened_file = open(target_file, "rb")
        data = opened_file.read()
    except:
        globals()['error'] = globals()['error'] + 1
        log(log_file, local_time + " [error] " + target_file + " does not exist or not enough privilege to read it")
    finally:
        if opened_file is not None:
            opened_file.close()

    # now we're ready to compare the hash values
    if opened_file is not None:
        byte_key = binascii.unhexlify(conf.TOKEN)
        signature_data = hmac.new(byte_key, data, hash_alg).hexdigest()

        if signature_data == expected_hash:
            # no changes, just write a notice in the log file
            log(log_file, local_time + " [notice] " + target_file + " ok")
        else:
            # hash has changed, warning

            # reporting aler in the log file
            globals()['warning'] = globals()['warning'] + 1
            message = local_time + " [warning] " + target_file + " changed"

            # pyHIDS log
            log(log_file, message, True)


def compare_command_hash(command, expected_hash, hash_alg, log_file):
    # each log's line contain the local time. it makes research easier.
    local_time = time.strftime("[%d/%m/%y %H:%M:%S]", time.localtime())

    proc = subprocess.Popen(command, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
    command_output = proc.stdout.read()
    byte_key = binascii.unhexlify(conf.TOKEN)
    hashed_data = hmac.new(byte_key, command_output, hash_alg).hexdigest()

    if hashed_data == expected_hash:
        # no changes, just write a notice in the log file
        log(log_file, local_time + " [notice] " + " ".join(command) + " ok")
    else:
        # hash has changed, warning

        # reporting aler in the log file
        globals()['warning'] = globals()['warning'] + 1
        message = local_time + " [warning] " + " ".join(command) + " command output has changed."

        # pyHIDS log
        log(log_file, message, True)

        # reporting alert in syslog        
        print(message)


@contextmanager
def opened_w_error(filename, mode="r"):
    try:
        f = open(filename, mode)
    except IOError as err:
        yield None, err
    else:
        try:
            yield f, None
        finally:
            f.close()


def log(log_file, message, display=True):
    """
    Print and save the log in the log file.
    """
    lock.acquire()
    if display:
        print(message)
    try:
        log_file.write(message + "\n")
    except Exception as e:
        print(e)
        # log_syslog(e)
    lock.release()


def check_base_integrity():
    with opened_w_error(conf.PUBLIC_KEY, "rb") as (public_key_dump, err):
        if err:
            print(str(err))
            exit(0)
        else:
            public_key = pickle.load(public_key_dump)

    with opened_w_error(conf.DATABASE_SIG, "rb") as (signature_file, err):
        if err:
            print(str(err))
            exit(0)
        else:
            signature = signature_file.read()

    with opened_w_error(conf.DATABASE, 'rb') as (msgfile, err):
        if err:
            print(str(err))
            exit(0)
        else:
            try:
                rsa.verify(msgfile, signature, public_key)
            except rsa.pkcs1.VerificationError as e:
                print("Integrity check of the base of hashes failed.")
                exit(0)


def pyHIDS():
    # Point of entry in execution mode
    # Verify the integrity of the base of hashes
    check_base_integrity()

    # open the log file
    log_file = None
    try:
        log_file = open(conf.LOGS, "a")
    except Exception as e:
        print("Something wrong happens when opening the logs: " + str(e))
        exit(0)
    log(log_file, time.strftime("[%d/%m/%y %H:%M:%S] HIDS starting.", time.localtime()))

    # dictionary containing filenames and their hash value.
    base = load_base()
    if base is None:
        print("Base of hash values can not be loaded.")
        exit(0)

    report = ""
    globals()['error'] = 0
    globals()['warning'] = 0

    if conf.ALG == 'sha256':
        hash_alg = hashlib.sha256
    elif conf.ALG == 'sha512':
        hash_alg = hashlib.sha512
    elif conf.ALG == 'sha3_256':
        hash_alg = hashlib.sha3_256
    elif conf.ALG == 'sha3_512':
        hash_alg = hashlib.sha3_512
    else:
        hash_alg = hashlib.sha256

    # Check existence of all the files following the rules and/or specified files
    scan_files()
    list_of_files = conf.SPECIFIC_FILES_TO_SCAN

    for rules in conf.FOLDER_RULES:
        list_of_files.extend(search_files(rules[0], rules[1]))
    number_of_files_to_scan = len(list_of_files)

    differences = set(list_of_files) - set(list(base["files"]))
    if differences:
        check_base_integrity()
        log(log_file, time.strftime("[%d/%m/%y %H:%M:%S] [notice] " + str(len(differences)) + " new file(s) found. "
                                                                                              "Adding it(them) to the "
                                                                                              "database.",
                                    time.localtime()))
        update_base(differences, hash_alg, log_file)

    # Check the integrity of monitored files
    list_of_threads = []
    for file in list(base["files"].keys()):
        if os.path.exists(file):
            thread = threading.Thread(None, compare_hash, None, (file, base["files"][file], hash_alg, log_file,))
            thread.start()
            list_of_threads.append(thread)

        else:
            globals()['error'] = globals()['error'] + 1
            log(log_file, time.strftime("[%d/%m/%y %H:%M:%S] [error] " + file + " does not exist or not enough "
                                                                                "privilege to read it.",
                                        time.localtime()))

    # Check the integrity of commands output
    for command in list(base["commands"].keys()):
        thread = threading.Thread(None, compare_command_hash, None, (command, base["commands"][command], hash_alg,
                                                                     log_file,))
        thread.start()
        list_of_threads.append(thread)

    # blocks the calling thread until the thread
    # whose join() method is called is terminated.
    for th in list_of_threads:
        th.join()

    while not Q.empty():
        report += Q.get(True, 0.5)

    local_time = time.strftime("[%d/%m/%y %H:%M:%S]", time.localtime())
    log(log_file, local_time + " Error(s) : " + str(globals()['error']))
    log(log_file, local_time + " Warning(s) : " + str(globals()['warning']))
    log(log_file, local_time + " HIDS finished.")

    if log_file is not None:
        log_file.close()


warning, error = 0, 0
