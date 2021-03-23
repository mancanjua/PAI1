#! /usr/bin/env python
#-*- coding: utf-8 -*-

"""This script generates the base of hash values.
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
__version__ = "$Revision: 0.2 $"
__date__ = "$Date: 2010/03/06 $"
__revision__ = "$Date: 2013/02/26 $"
__copyright__ = "Copyright (c) 2010-2018 Cedric Bonhomme"
__license__ = "GPL v3"

import hashlib
import pickle
import subprocess
import os
import re
import rsa
import conf
import time
import hmac
import binascii


def search_files(motif, root_path):
    """
    Return a list of files.

    Search fo files containing 'motif' that
    aren't symbolic links.
    """
    result = []
    w = os.walk(root_path)
    for (path, dirs, files) in w:
        for f in files:
            if re.compile(motif).search(f):
                # if not a symbolic link
                if not os.path.islink(os.path.join(path, f)):
                    result.append(os.path.join(path, f))
    return result


def calculate_hmac(target_file, hash_alg):
    byte_key = binascii.unhexlify(conf.TOKEN)
    opened_file = None
    signature_data = None
    data = None
    try:
        opened_file = open(target_file, "rb")
        data = opened_file.read()
    except Exception as e:
        print(target_file, ":", e)
        globals()['number_of_files_to_scan'] = globals()['number_of_files_to_scan'] - 1
    finally:
        if data is not None:

            opened_file.close()
    if data is not None:
        signature_data = hmac.new(byte_key, data, hash_alg).hexdigest()
    return signature_data


def update_base(new_files, hash_alg, log_file):
    from pyHIDS import load_base, log

    base = load_base()

    for file in new_files:
        file_hash = calculate_hmac(file, hash_alg)
        if file_hash is not None:
            log(log_file, time.strftime("[%d/%m/%y %H:%M:%S] [notice] " + file + " added to the database.",
                              time.localtime()))
            base["files"][file] = file_hash

    serialized_db = open(conf.DATABASE, "wb")
    pickle.dump(base, serialized_db)
    serialized_db.close()

    log(log_file, time.strftime("[%d/%m/%y %H:%M:%S] [notice] " + str(len(new_files)) + " file(s) added to the "
                                                                                        "database.",
                                time.localtime()))

    sign_database()


def sign_database():
    # Loads the private key
    with open(conf.PRIVATE_KEY, "rb") as private_key_dump:
        private_key = pickle.load(private_key_dump)

    # Sign the database of hash
    with open(conf.DATABASE, 'rb') as msgfile:
        signature = rsa.sign(msgfile, private_key, 'SHA-256')

    # Writes the signature in a file.
    with open(conf.DATABASE_SIG, "wb") as signature_file:
        signature_file.write(signature)


def genBase():
    # Point of entry in execution mode.
    database = {}
    database["files"] = {}
    database["commands"] = {}

    # load the specific files to scan
    list_of_files = conf.SPECIFIC_FILES_TO_SCAN

    # adding the folders with rules to scan :
    for rules in conf.FOLDER_RULES:
        list_of_files.extend(search_files(rules[0], rules[1]))
    number_of_files_to_scan = len(list_of_files)

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

    print("Generating database...")
    # Compute the hash values of each files
    for a_file in list_of_files:
        hash_value = calculate_hmac(a_file, hash_alg)
        if hash_value is not None:
            database["files"][a_file] = hash_value

    # Compute the hash values of each commands
    byte_key = binascii.unhexlify(conf.TOKEN)
    for command in conf.COMMANDS:
        proc = subprocess.Popen((command), stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        command_output = proc.stdout.read()
        hashed_data = hmac.new(byte_key, command_output, hash_alg).hexdigest()
        database["commands"][command] = hashed_data

    serialized_database = open(conf.DATABASE, "wb")
    pickle.dump(database, serialized_database)
    serialized_database.close()

    print(number_of_files_to_scan, "files in the database.")

    sign_database()
