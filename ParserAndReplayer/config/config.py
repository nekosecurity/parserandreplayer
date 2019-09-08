# -*- coding: utf-8 -*-
from __future__ import absolute_import
from sys import path

from configparser import ConfigParser
from ParserAndReplayer.log import *
from os import getcwd
from os.path import exists
import os.path
import shutil

user_config_dir = os.path.expanduser("~") + "/.config/ParserAndReplayer"
user_config = user_config_dir + "/ParserAndReplayer.conf"

if not os.path.isfile(user_config):
    os.makedirs(user_config_dir, exist_ok=True)
    shutil.copyfile(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'ParserAndReplayer.conf')
        , user_config)



parser = ConfigParser()
parser.read(user_config)
output_dir = getcwd()

def check_if_tools_exists():
    for section in parser.sections():
        for tool_name, tool_path in parser.items(section):
            if not exists(tool_path):
                rootlogger.warning("%s not found" % (tool_name))


check_if_tools_exists()

sslscan = parser.get("SSL tools", "sslscan")
testssl = parser.get("SSL tools", "testssl")
sshaudit = parser.get('SSH tools', "ssh-audit")
show_smb_version = parser.get('SMB tools', 'show_smb_version')
rdp_sec_check = parser.get('RDP tools', 'rdp_sec_check')
rdp_check_ciphers = parser.get('RDP tools', 'rdp_check_ciphers')
hping = parser.get('Network tools', 'hping3')
icmpquery = parser.get('Network tools', 'icmpquery')
