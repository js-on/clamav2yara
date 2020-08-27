#!/usr/bin/env python3
'''
File name: clamav2yara.py
Author: Jakob Schaffarczyk
Date created: 8/27/2020
Date last modified: 8/27/2020
Python Version: 3.7.4
'''


import subprocess
import argparse
import requests
import glob
import sys
import re
import os


# DOWNLOAD CLAMAV VIRUS DATABASE AND EXTRACT DATA
def download(url, dbfile):
    with open(dbfile, "wb") as db:
        print("Downloading", dbfile)
        response = requests.get(url, stream=True)
        total_length = response.headers.get('content-length')

        if total_length is None:
            f.write(response.content)
        else:
            dl = 0
            total_length = int(total_length)
            for data in response.iter_content(chunk_size=4096):
                dl += len(data)
                db.write(data)
                done = int(100 * dl / total_length)
                sys.stdout.write("\r[%s%s]" % ('#'*done, ' '*(100-done)))
                sys.stdout.flush()
    print()

    print("Extracting data from", DB_FILE)
    proc = subprocess.Popen(["sigtool", "-u", DB_FILE])
    proc.wait()


# MERGE ALL AVAILABLE .YARA RULES
def merge():
    rules = glob.glob("*.yara")
    with open("total.yara", 'w') as total:
        for yara in rules:
            total.write(open(yara, 'r').read())


# STATUS BAR FOR CONVERSION PROCESS
def status(msg, pos, limit, width):
    x = int((width/limit)*pos)
    print(f"{msg} [{x*'#'}{(width-x)*' '}] {pos}/{limit}", end='\r')
    if pos == limit:
        print(f"{msg} [{x*'#'}{(width-x)*' '}] {pos}/{limit}", end='\r')
        print()


# BATCH REPLACEMENT BY USING DICT
# {'key to replace': 'replacement'}
def repl(s, sub):
    for i in sub.keys():
        s = s.replace(i, sub[i])

    return s.replace("\n", "")


# SHORT CONDITIONS BASED ON LAMBDA FUNCTIONS
def check(var, condition, expVal, msg):
    if not CONDITION[condition](var, expVal):
        print(msg)
        exit(1)


# GET FILETYPE FROM FILENAME
def get_file_ext(fname):
    return re.findall(REGEX['ftype'], fname)[1]


# REFORMAT NDB STRING TO YARA
def formatNDB(string):
    string = repl(string, {
        "{": "[",
        "}": "]",
        "[-": "[0-"
    })
    if string.endswith("]"):
        string = re.sub(r'\[\d+\-?\d*\]$', '', string)
    if string.endswith(")"):
        string = re.sub(r'\([\|0-9A-F]*\)$', '', string)

    return string


# REFORMAT NDU STRING TO YARA
def formatNDU(string):
    string = repl(string, {
        "{": "[",
        "}": "]",
        "[-": "[0-"
    })
    if string.endswith("]"):
        string = re.sub(r'\[\d+\-?\d*\]$', '', string)
    if string.endswith(")"):
        string = re.sub(r'\([\|0-9A-F]*\)$', '', string)

    return string


# CREATE RULE FROM NDB STRINGS
def convertNDB(line):
    name = re.findall(REGEX['name'], line)[0]
    strings = re.findall(REGEX['strings'], line)[
        3].replace("\n", "").split("*")
    rule = f"""
rule {repl(name, {'.': '_', '-': '_', '/': '_'})}
{{
    strings:
{FORMAT['nl'].join([f"{3*FORMAT['tab']}$a{i} = {{ {formatNDB(strings[i])} }}" for i in range(len(strings))])}

    condition:
        any of them
}}"""

    return rule


# CREATE RULE FROM NDU STRINGS
def convertNDU(line):
    name = re.findall(REGEX['name'], line)[0]
    strings = re.findall(REGEX['strings'], line)[
        3].replace("\n", "").split("*")
    rule = f"""
rule {repl(name, {'.': '_', '-': '_', '/': '_'})}
{{
    strings:
{FORMAT['nl'].join([f"{3*FORMAT['tab']}$a{i} = {{ {formatNDU(strings[i])} }}" for i in range(len(strings))])}

    condition:
        any of them
}}"""

    return rule


# CREATE RULE FROM HSB STRINGS
def convertHSB(line):
    md5 = line.split(":")[0].replace("\n", "")
    name = line.split(":")[2].replace("\n", "")
    rule = f"""
rule {repl(name, {'.': '_', '-': '_', '/': '_'})}
{{
    condition:
        hash.md5(0, filesize) == "{md5}"
}}"""

    return rule


# CREATE RULE FROM HDB STRINGS
def convertHDB(line):
    md5 = line.split(":")[0].replace("\n", "")
    name = line.split(":")[2].replace("\n", "")
    rule = f"""
rule {repl(name, {'.': '_', '-': '_', '/': '_'})}
{{
    condition:
        hash.md5(0, filesize) == "{md5}"
}}"""

    return rule


# VARIABLES
INPUT = None
OUTPUT = None
TYPE = None
URL = "http://database.clamav.net/daily.cvd"
DB_FILE = "daily.cvd"
EXTENSIONS = ['.ndu', '.ndb', '.hdb', '.hsb']


# SETTINGS
MODES = {
    'NDU': convertNDU,
    'NDB': convertNDB,
    'HDB': convertHDB,
    'HSB': convertHSB
}

CONDITION = {
    'ne': lambda var, expVal: var != expVal,
    'eq': lambda var, expVal: var == expVal,
    'sw': lambda var, expVal: var.startswith(expVal),
    'snw': lambda var, expVal: not var.startswith(expVal),
    'ew': lambda var, expVal: var.endswith(expVal),
    'enw': lambda var, expVal: not var.endswith(expVal),
    'in': lambda var, expVal: var in expVal,
    'nin': lambda var, expVal: var not in expVal
}

REGEX = {
    'name': re.compile(r'[^:]+'),
    'strings': re.compile(r'[^:]+'),
    'ftype': re.compile(r'.[^.]+')
}

FORMAT = {
    'tab': '\t',
    'nl': '\n'
}


# WRITE RULE TO OUTFILE
def write(outfile, rule):
    with open(outfile, 'a') as of:
        of.write(rule)


# WRITE IMPORT TO OUTFILE
def setup(filename):
    with open(filename, 'w') as yara:
        yara.write("import \"hash\"\n")


# ARGPARSE
parser = argparse.ArgumentParser()
parser.add_argument('-i', metavar='inputfile', type=str,
                    help=f'clamav database [{", ".join(EXTENSIONS)}]')
parser.add_argument('-o', metavar='outputfile', type=str,
                    help='yara ruleset [.yara]')
parser.add_argument(
    '-a', help="convert all supported filetypes to .yara files", action="store_true")
parser.add_argument(
    '-d', help="download current clamav virus database", action="store_true")
parser.add_argument(
    '-m', help="merge all available yara rules", action="store_true")
args = parser.parse_args()

if args.i and args.o:
    check(get_file_ext(args.i), 'in', EXTENSIONS,
          f'Wrong input file format, [{", ".join(EXTENSIONS)}]')
    check(get_file_ext(args.o), 'eq', '.yara',
          'Wrong output file format, [.yara]')
    INPUT = args.i
    OUTPUT = args.o
    TYPE = get_file_ext(INPUT)[1:].upper()

    if TYPE in ["HDB", "HSB"]:
        setup(OUTPUT)

    limit = sum(1 for line in open(INPUT, 'r'))
    with open(INPUT, 'r') as f:
        c = 1
        for line in f:
            write(OUTPUT, MODES[TYPE](line))
            status("Converted", c, limit, 100)
            c += 1

elif args.a:
    for t in EXTENSIONS:
        TYPE = t[1:].upper()
        INPUT = "daily" + t
        OUTPUT = "daily_" + t[1:] + ".yara"
        limit = sum(1 for line in open(INPUT, 'r'))
        with open(INPUT, 'r') as f:
            c = 1
            for line in f:
                write(OUTPUT, MODES[TYPE](line))
                status("Converted " + TYPE, c, limit, 100)
                c += 1
elif args.m:
    merge()

elif args.d:
    download(URL, DB_FILE)

else:
    parser.print_help(sys.stderr)
