#!/usr/bin/env python3

import argparse
from sys import argv
from ParserAndReplayer.parser import nessus
from ParserAndReplayer.log import rootlogger
from ParserAndReplayer.plugins.replay_ssh import ReplaySSH
from ParserAndReplayer.plugins.replay_ssl import ReplaySSL
from ParserAndReplayer.plugins.replay_rdp import ReplayRDP
from ParserAndReplayer.plugins.replay_banner import ReplayBanner


class NessusAnalyze:
    def __init__(self, filename, options):
        self.n = nessus.Nessus(filename)
        self.fullinfo = options.fullinfo
        self.verbose = options.verbose
        if options.logger != 1:
            rootlogger.setLevel(options.logger)

        self.prepare_call(options)

    def prepare_call(self, options):
        if options.pluginName:
            self.pluginNames(options.pluginName)
        if options.pluginID:
            self.pluginIDs(options.pluginID)
        if options.severity:
            self.severities(options.severity)
        if options.metasploit_exploit:
            self.metasploit_exploit()
        if options.canvas_exploit:
            self.canvas_exploit()
        if options.nessus_exploit:
            self.nessus_exploit()
        if options.core_exploit:
            self.metasploit_exploit()
        if options.port:
            self.ports(options.port)
        if options.ip:
            self.ips(options.ip)
        if options.cvss:
            self.cvss(options.cvss)
        if options.cve:
            self.cve()
        if options.all_vuln_name:
            self.all_vuln_name()
        if options.statistics:
            self.statistics()


    def pluginNames(self, pluginNames):
        results = self.n.find_by_pluginNames(self.fullinfo, *pluginNames)
        if self.verbose:
            print(results)

    def pluginIDs(self, pluginIDs):
        results = self.n.find_by_pluginIDs(self.fullinfo, *pluginIDs)
        if self.verbose:
            print(results)

    def severities(self, severities):
        results = self.n.find_by_severities(self.fullinfo, *severities)
        if self.verbose:
            print(results)

    def metasploit_exploit(self):
        results = self.n.find_by_metasploit_exploitability(self.fullinfo)
        if self.verbose:
            print(results)

    def canvas_exploit(self):
        result = self.n.find_by_canvas_exploitability(self.fullinfo)
        if self.verbose:
            print(results)

    def nessus_exploit(self):
        results = self.n.find_by_nessus_exploitability(self.fullinfo)
        if self.verbose:
            print(results)

    def core_exploit(self):
        results = self.n.find_by_core_exploitability(self.fullinfo)
        if self.verbose:
            print(results)

    def ports(self, ports):
        results = self.n.find_by_ports(self.fullinfo, *ports)
        if self.verbose:
            print(results)

    def ips(self, ips):
        results = self.n.find_by_ips(self.fullinfo, *ips)
        if self.verbose:
            print(results)

    def cvss(self, cvss):
        results = self.n.find_by_cvss(cvss, self.fullinfo)
        if self.verbose:
            print(results)

    def cve(self):
        results = self.n.find_all_cve(updatedb=True)
        if self.verbose:
            print(results)

    def all_vuln_name(self):
        results = self.n.find_all_vuln_name(self.fullinfo)
        if self.verbose:
            print(results)

    def statistics(self):
        self.n.print_statistics()



if __name__ == "__main__":
    desc = "Parse nessus"
    example = "python extract.py file.nessus analyze --cve --verbose"
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=desc, epilog=example)

    # Options
    options = parser.add_argument_group('Options')
    options.add_argument('--verbose', help="Show ips with results", action="store_true")
    options.add_argument('--fullinfo', help="Show all vulnerability details", action="store_true", default=False)
    options.add_argument('--logger', help="Change the level of logger", type=int, default=1)

    # Analyzer
    types = parser.add_subparsers()
    type_analyzer= types.add_parser("analyze", help="Performs an analysis of the nessus file")
    type_analyzer.add_argument('--pluginName', help="Search IP addresses impacted by the Nessus plugins names", nargs="+")
    type_analyzer.add_argument('--pluginID', help="Search IP addresses impacted by the Nessus plugins ID", nargs="+")
    type_analyzer.add_argument('--severity', help="Search for ip addresses impacted by vulnerabilities of severity defined by Nessus.", nargs="+")
    type_analyzer.add_argument('--port', help="Search for ports impacted by vulnerabilities.", nargs="+")
    type_analyzer.add_argument('--ip', help="Search for ips impacted by vulnerabilities.", nargs="+")
    type_analyzer.add_argument('--cvss', help="Search for vulnerabilities with a CVSS score equal or higher.", type=float)
    type_analyzer.add_argument('--cve', help="Search for ips impacted by vulnerabilities.", action="store_true")
    type_analyzer.add_argument('--all-vuln-name', help="Search all vulnerabilities contained in the.nessus file", action="store_true")
    type_analyzer.add_argument('--statistics', help="Print statistics about parsed reports", action="store_true")

    type_analyzer.add_argument('--metasploit_exploit', help="Search for ip addresses impacted by vulnerabilities that can be exploited by Metasploit", action="store_true")
    type_analyzer.add_argument('--canvas_exploit', help="Search for ip addresses impacted by vulnerabilities that can be exploited by Canvas.", action="store_true")
    type_analyzer.add_argument('--nessus_exploit', help="Search for ip addresses impacted by vulnerabilities that can be exploited by Nessus.", action="store_true")
    type_analyzer.add_argument('--core_exploit', help="Search for ip addresses impacted by vulnerabilities that can be exploited by Core Impact.", action="store_true")


    # Mandatory
    mandatory = parser.add_argument_group("Mandatory")
    mandatory.add_argument("filename", help='.nessus file', nargs='?')



    #TODO
    type_replay = types.add_parser("replay", help="Replays the nessus traces")
    args = parser.parse_args()

    if len(argv) < 2:
        parser.print_help()
        exit(-1)

    filename = args.filename
    if filename is None:
        parser.print_help()
        exit(-2)

    NessusAnalyze(filename, args)
