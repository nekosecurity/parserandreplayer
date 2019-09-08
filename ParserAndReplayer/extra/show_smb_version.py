#!/usr/bin/env python

from impacket.smbconnection import SMBConnection, SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SessionError
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.rpcrt import  DCERPCException
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from sys import argv
import argparse
from os import path

from re import search, compile
from socket import gethostbyname

class SMBRecon:
    def __init__(self, host, port, smbversion):
        self.host = host
        self.port = port
        self.smbversion = smbversion

        self.smb = self.__connect(host, int(port))
        self.__getSmbProtocolVersion()
        self.show(host)

    def get_os_arch(self, host):
        try:
            stringBinding = r'ncacn_ip_tcp:{}[135]'.format(host)
            transport = DCERPCTransportFactory(stringBinding)
            transport.set_connect_timeout(5)
            dce = transport.get_dce_rpc()
            dce.connect()
            try:
                dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
            except DCERPCException as e:
                if str(e).find('syntaxes_not_supported') >= 0:
                    dce.disconnect()
                    return 32
            else:
                dce.disconnect()
                return 64

        except Exception as e:
            print('Error retrieving os arch of {}: {}'.format(host, str(e)))

        return 0

    def __connect(self, host, port):
        if self.smbversion == "1":
            dialect = SMB_DIALECT
        elif self.smbversion == "2":
            dialect = SMB2_DIALECT_002
        elif self.smbversion == "2.1":
            dialect = SMB2_DIALECT_21
        else:
            dialect = None

        if port == 139:
            smb = SMBConnection('*SMBSERVER', host, sess_port=port, timeout=10)
        else:
            # timeout=60 by default
            smb = SMBConnection(host, host, sess_port=port, preferredDialect=dialect)
        return smb

    def __getSmbProtocolVersion(self):
        dialect = self.smb.getDialect()
        if dialect == SMB_DIALECT:
            print("SMBv1 dialect used")
            return "SMBv1 dialect used"
        elif dialect == SMB2_DIALECT_002:
            print("SMBv2.0 dialect used")
            return "SMBv2.0 dialect used"
        elif dialect == SMB2_DIALECT_21:
            print("SMBv2.1 dialect used")
            return "SMBv2.1 dialect used"
        else:
            print("SMBv3.0 dialect used")
            return "SMBv3.0 dialect used"

    def show(self, host):
        try:
            self.smb.login('', '')
        except SessionError as e:
            if "STATUS_ACCESS_DENIED" in e.message:
                pass
        print("SMB signing: %s" % self.smb.isSigningRequired())
        print("SMB login required: %s" % self.smb.isLoginRequired())
        print("Domain: %s" % self.smb.getServerDomain())
        print("Hostname: %s" % self.smb.getServerName())
        print("OS: %s" % self.smb.getServerOS())
        print("Build: %s" % self.smb.getServerOSBuild())
        print("Arch: %s" % self.get_os_arch(host))

if __name__ == '__main__':
    desc = "Show SMB informations"
    example = "python show_smb_version.py 127.0.0.1"
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=desc, epilog=example)

    # Mandatory
    mandatory = parser.add_argument_group("Mandatory")
    mandatory.add_argument("target", help="IP or hostname(s)")

    # General settings
    generalSettings = parser.add_argument_group("General Settings")
    generalSettings.add_argument("--dialect", help="Select SMB dialec", default="1", choices=["1","2","2.1","3"], type=str)

    args = parser.parse_args()
    if len(argv) < 2:
        print(args)
        parser.print_help()
        exit(-1)

    target = args.target
    SMBRecon(target.split(':')[0], target.split(':')[1], str(args.dialect))
