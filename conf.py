#! /usr/bin/env python
#-*- coding: utf-8 -*-

""" Program variables.

This file contain the variables used by pyHIDS.
"""

"""
pyHIDS. Python HIDS. Security software.
pyHIDS verify the integrity of your system.
Copyright (C) 2010-2013 Cedric Bonhomme

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

pyHIDS Copyright (C) 2010-2013 Cedric Bonhomme
This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
This is free software, and you are welcome to redistribute it
under certain conditions; type `show c' for details.
"""

__author__ = "Cedric Bonhomme"
__version__ = "$Revision: 0.2 $"
__date__ = "$Date: 2013/02/16 $"
__revision__ = "$Date: 2014/01/07 $"
__copyright__ = "Copyright (c) 2010-2014 Cedric Bonhomme"
__license__ = "GPL v3"

import os
import configparser
# load the configuration


config = configparser.ConfigParser()

try:
    with open('conf.cfg') as f:
        config.read_file(f)
except IOError:
    config.read('conf.cfg-sample')

PATH = os.path.abspath(".")

NB_BITS = int(config.get('globals', 'nb_bits'))

TIMER = int(config.get('globals', 'timer'))

ALG = config.get('globals', 'alg')

TOKEN = config.get('globals', 'token')

# address of the log file :
LOGS = os.path.join(PATH, "log")
# address of the database of hash values :
DATABASE = os.path.join(PATH, "base")
# address of the signature of the database:
DATABASE_SIG = os.path.join(PATH, "database.sig")

# path of the private key (to sign the database of hash values) :
PRIVATE_KEY = os.path.join(PATH, "pyhids_rsa")
# path of the public key (to check the integrity of the database) :
PUBLIC_KEY = os.path.join(PATH, "pyhids_rsa.pub")

# specific files to scan :
SPECIFIC_FILES_TO_SCAN = [
    os.path.join(PATH, "pyHIDS.py"),
    os.path.join(PATH, "conf.py")]
for name, current_file in config.items("files"):
    SPECIFIC_FILES_TO_SCAN.append(current_file)

# rules to scan folders : ]
FOLDER_RULES = []
for name, rule in config.items("rules"):
    pattern, folder = rule.split(' ')
    FOLDER_RULES.append((pattern, folder))

# Output of commands :
COMMANDS = []
for name, command in config.items("commands"):
    COMMANDS.append(tuple(command.split(' ')))


def scan_files():
    # specific files to scan :
    globals()['SPECIFIC_FILES_TO_SCAN'] = [
        os.path.join(PATH, "pyHIDS.py"),
        os.path.join(PATH, "conf.py")]
    for name, current_file in config.items("files"):
        SPECIFIC_FILES_TO_SCAN.append(current_file)

    # rules to scan folders : ]
    globals()['FOLDER_RULES'] = []
    for name, rule in config.items("rules"):
        pattern, folder = rule.split(' ')
        FOLDER_RULES.append((pattern, folder))
