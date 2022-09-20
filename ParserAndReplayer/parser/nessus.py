from ParserAndReplayer.lib import neko_libparser
from ParserAndReplayer.log import *
import ParserAndReplayer.helpers.display as pdisplay
import importlib.resources
from pprint import pprint
import json
import sys, os

#    {
#        report {
#        name: '',
#        report_host: [{
#            ip: '',
#            hosts_properties: {
#                tags: {[
#                    name: '',
#                    value: '',
#                ]}
#            }
#            report_items: [{
#
#            }]
#        }]
#    }

class Nessus:
    """
    Parser to perform informative extraction from .nessus files format.
    """
    _LOCAL = 'local'
    _REMOTE = 'remote'
    _COMBINED = 'combined'
    _blacklist = [
        "11154", # Unknown Service Detection
        "19506", # Nessus Scan Information
        "45590", # Common Platform Enumeration
        "56468", # Time of Last System Startup
        "57033", # Microsoft Patch Bulletin Feasibility Check
        "10287", # Traceroute Information
    ]
    _blacklist_hit = 0

    def __init__(self, filename, verbose=False, output="table"):
        if filename == None or filename == "":
            print("[!] No filename specified!")
            exit(-1)
        if filename.endswith(".nessus"):
            self._results = neko_libparser.parse_nessus(filename)
            self.verbose = verbose
            self.display = pdisplay.display(output)
        else:
            print("[!] No file .nessus to parse was found!")
            exit(-2)

    def _all_info(self, host, vuln):
        r"""
        Display all information about the vulnerability
        """
        print('Host: %s:%s\n'
                        'Plugin Name: %s\n'
                        'Plugin ID: %s\n'
                        'Plugin Type: %s\n'
                        'Service Name: %s\n'
                        'Severity: %s\n'
                        'Risk Factor: %s\n'
                        'Exploit Available: %s\n'
                        'Exploitability Ease: %s\n'
                        'OSVDB: %s\n'
                        'CVE: %s\n'
                        'CVSS Base Score: %s\n'
                        'CVSS3 Base Score: %s\n'
                        'See Also: %s\n'
                        'Description: %s\n'
                        'Solution: %s\n'
                        'Plugin Output: %s\n'
                        'Nessus Script: %s\n'
                        'Exploited by Nessus: %s\n'
                        'Exploit Metasploit: %s\n'
                        'Exploit Canvas: %s\n'
                        'Exploit Core Impact: %s\n'
                        'Exploit D2 Elliot: %s' % (host, vuln['port'], vuln['pluginName'], vuln['pluginID'],
                                                     vuln['plugin_type'], vuln['svc_name'], vuln['severity'],
                                                     vuln['risk_factor'], vuln['exploit_available'],
                                                     vuln['exploitability_ease'], str(vuln['osvdb']),
                                                     vuln['cve'], vuln['cvss_base_score'],
                                                     vuln['cvss3_base_score'], vuln['see_also'], vuln['description'], vuln['solution'],
                                                     vuln['plugin_output'], vuln['nessus_script'],vuln['exploited_by_nessus'],
                                                     vuln['metasploit'],vuln['canvas'], vuln['core'], vuln['d2_elliot']
                                                     )
                        )

    def find_by_pluginID(self, pluginID, fullinfo=False):
        r"""find_by_pluginID(80101) -> set
        Search IP addresses impacted by the Nessus plugin ID.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """
        if type(pluginID) is int:
            pluginID = str(pluginID)
        if not pluginID.isdigit():
            print("[!] PluginID format error.")
            exit(-2)

        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                if vuln['pluginID'] == pluginID:
                    if fullinfo == True:
                        self._all_info(host['ip'], vuln)
                    results.add(host['ip'] + ":" + vuln['port'])
                    r2.add((host['ip'], vuln["port"], vuln['pluginName'], vuln['pluginID']))
        if self.verbose:
            self.display(["IP", "Port", "Vulnerability", "Plugin ID"], sorted(r2))
        return results

    def find_by_pluginIDs(self, fullinfo=False, *pluginsIDS):
        r"""find_by_pluginIDS("80101", 80102) -> set
        Search IP addresses impacted by multiples Nessus plugins ID.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """

        results = list()
        for pluginsID in pluginsIDS:
            results.extend(self.find_by_pluginID(pluginsID, fullinfo))
        results = set(results)
        return results

    def find_by_pluginName(self, pluginName, fullinfo=False):
        r"""find_by_pluginName("SSH") -> set
        Search IP addresses impacted by the Nessus plugins names.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """
        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                if vuln['pluginName'].lower().find(pluginName.lower()) >= 0:
                    if fullinfo == True:
                        self._all_info(host['ip'], vuln)
                    r2.add((host['ip'], vuln["port"], vuln['pluginName'], vuln['pluginID']))
                    results.add(host['ip']+':'+vuln['port'])
        if self.verbose:
            self.display(["IP", "Port", "Vulnerability", "Plugin ID"], sorted(r2))
        return results

    def find_by_pluginNames(self, fullinfo=False, *pluginNames):
        r"""find_by_pluginNames("SSL", "ssh") -> set
        Search IP addresses impacted by multiples Nessus plugins name.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """

        results = list()
        for pluginName in pluginNames:
            results.extend(self.find_by_pluginName(pluginName, fullinfo))
        results = set(results)
        return results

    def find_by_severities(self, fullinfo=False, *severities):
        r"""find_by_severities("1", "critical", 2) -> set
        Search for ip addresses impacted by vulnerabilities of multiples severity defined by Nessus.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """

        results = list()
        for severity in severities:
            results.extend(self.find_by_severity(severity, fullinfo))
        results = set(results)
        return results

    def find_by_severity(self, severity, fullinfo=False):
        r"""find_by_severity("critical") -> set
        Search for ip addresses impacted by vulnerabilities of severity defined by Nessus.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """
        if type(severity) is int:
            severity = str(severity)
        if severity.lower() == "info":
            severity = '0'
        if severity.lower() == "low":
            severity = '1'
        if severity.lower() == "medium":
            severity = '2'
        if severity.lower() == "high":
            severity = '3'
        if severity.lower() == "critical":
            severity = '4'

        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                if vuln['severity'] == severity:
                    if fullinfo == True:
                        self._all_info(host['ip'], vuln)
                    results.add(host['ip']+":"+vuln['port'])
                    r2.add((host['ip'], vuln["port"], vuln['pluginName'], vuln['pluginID']))
        if self.verbose:
            self.display(["IP", "Port", "Vulnerability", "Plugin ID"], sorted(r2))
        return results

    def find_by_metasploit_exploitability(self, fullinfo=False):
        r"""find_by_metasploit_exploitability() -> set
        Search for ip addresses impacted by vulnerabilities that can be exploited by Metasploit.

        Returns:
           A collection containing all ip addresses and ports, and the metasploit exploit name if available,
           or an empty collection if no address is found.
        """
        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                if vuln['metasploit'] == True:
                    if fullinfo == True:
                        self._all_info(host['ip'], vuln)
                    results.add(host['ip']+":"+vuln["port"]+" -> " + str(vuln['metasploit_name']))
                    r2.add((host['ip'], vuln["port"], vuln['pluginName'] + f"({vuln['pluginID']})", str(vuln['metasploit_name'])))
        if self.verbose:
            self.display(["IP", "Port", "Vulnerability (PluginID)", "Metasploit exploit"], sorted(r2))
        return results
    
    def find_by_d2_elliot_exploitability(self, fullinfo=False):
        r"""find_by_d2_elliot_exploitability() -> set
        Search for ip addresses impacted by vulnerabilities that can be exploited by D2 Elliot.

        Returns:
           A collection containing all ip addresses and ports, and the d2 elliot exploit name if available,
           or an empty collection if no address is found.
        """
        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                if vuln['d2_elliot'] == True:
                    if fullinfo == True:
                        self._all_info(host['ip'], vuln)
                    results.add(host['ip']+":"+vuln["port"]+" -> " + str(vuln['d2_elliot_name']))
                    r2.add((host['ip'], vuln["port"], vuln['pluginName'] + f"({vuln['pluginID']})", vuln['d2_elliot_name']))
        if self.verbose:
            self.display(["IP", "Port", "Vulnerability (PluginID)", "D2 Elliot exploit"], sorted(r2))    
        return results

    def find_by_canvas_exploitability(self, fullinfo=False):
        r"""find_by_canvas_exploitability() -> set
        Search for ip addresses impacted by vulnerabilities that can be exploited by Canvas.

        Returns:
           A collection containing all ip addresses and ports, and the canvas exploit name if available,
           or an empty collection if no address is found.
        """
        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                if vuln['canvas'] == True:
                    if fullinfo == True:
                        self._all_info(host['ip'], vuln)
                    results.add(host['ip']+":"+vuln['port']+" -> " + str(vuln['canvas_package']))
                    r2.add((host['ip'], vuln["port"], vuln['pluginName'] + f"({vuln['pluginID']})", str(vuln['canvas_package'])))
        if self.verbose:
            self.display(["IP", "Port", "Vulnerability (PluginID)", "Canvas exploit"], sorted(r2))
        return results

    def find_by_nessus_exploitability(self, fullinfo=False):
        r"""find_by_nessus_exploitability() -> set
        Search for ip addresses impacted by vulnerabilities that can be exploited by Nessus.

        Returns:
           A collection containing all ip addresses and ports and exploited,
           or an empty collection if no address is found.
        """
        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                if vuln['exploited_by_nessus'] == True:
                    if fullinfo == True:
                        self._all_info(host['ip'], vuln)
                    results.add(host['ip'] + ":" + vuln['port'] + " -> " + str(vuln['exploited_by_nessus']))
                    r2.add((host['ip'], vuln["port"], vuln['pluginName'] + f"({vuln['pluginID']})", vuln['exploited_by_nessus']))
        if self.verbose:
            self.display(["IP", "Port", "Vulnerability (PluginID)", "Nessus exploit"], sorted(r2))
        return results

    def find_by_core_exploitability(self, fullinfo=False):
        r"""find_by_core_exploitability() -> set
        Search for ip addresses impacted by vulnerabilities that can be exploited by Core Impact.

        Returns:
           A collection containing all ip addresses and ports,
           or an empty collection if no address is found.
        """

        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                if vuln['core'] == True:
                    if fullinfo == True:
                        self._all_info(host['ip'], vuln)
                    results.add(host['ip'] + ":" + vuln['port'])
                    r2.add((host['ip'], vuln["port"], vuln['pluginName'] + f"({vuln['pluginID']})", "\n".join(vuln['core_exploit'])))
        if self.verbose:
            self.display(["IP", "Port", "Vulnerability (PluginID)", "Canvas exploit"], sorted(r2))
        return results

    def find_by_ports(self, fullinfo=False, *ports):
        r"""find_by_ports("22", 80) -> set
        Search for ports impacted by vulnerabilities.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """

        results = list()
        for port in ports:
            results.extend(self.find_by_port(port, fullinfo))
        results = set(results)
        return results

    def find_by_port(self, port, fullinfo=False):
        r"""find_by_port("22") -> set
        Search for port impacted by vulnerabilities.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """
        if type(port) is int:
            port = str(port)

        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                if vuln['port'] == str(port):
                    if fullinfo == True:
                        self._all_info(host, vuln)
                    results.add(host['ip']+":"+vuln['port'])
                    r2.add((host['ip'], vuln["port"], vuln['pluginName'], vuln['pluginID']))
            if self.verbose:
                self.display(["IP", "Port", "Vulnerability", "PluginID"], sorted(r2))
        return results

    def find_by_ips(self, fullinfo=False, *ips):
        r"""find_by_ips("127.0.0.1", "192.168.0.1") -> set
        Search for vulnerabilities impacting ip addresses.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """

        results = list()
        for ip in ips:
            results.extend(self.find_by_ip(ip, fullinfo))
        results = set(results)
        return results

    def find_by_ip(self, ip, fullinfo=False):
        r"""find_by_ip("127.0.0.1") -> set
        Search for vulnerabilities impacting ip address.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """
        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            if host['ip'] == ip:
                vulns = host['report_items']
        for vuln in vulns:
            if fullinfo == True:
                self._all_info(ip, vuln)
            results.add(ip+":"+vuln['port'])
            r2.add((host['ip'], vuln["port"], vuln['pluginName'], vuln['pluginID']))
        if self.verbose:
            self.display(["IP", "Port", "Vulnerability", "PluginID"], sorted(r2))
        return results

    def find_by_cvss(self, cvss, fullinfo=False):
        r"""find_by_cvss("5") -> set
        Search for vulnerabilities with a CVSS score equal or higher.

        When the logger is in "INFO" mode, the ips addresses are displayed on the standard output.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """
        _cvss = float(cvss)
        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                try:
                    if float(vuln['cvss_base_score']) >= float(_cvss):
                        cvss = float(vuln['cvss_base_score'])
                    if float(vuln['cvss3_base_score']) >= float(_cvss):
                        cvss3 = float(vuln['cvss3_base_score'])
                    else:
                        break
                    if fullinfo == True:
                        self._all_info(host['ip'], vuln)
                    #else:
                    #    rootlogger.info("%s:%s [ID %s] %s (Score CVSS: %0.1f, Score CVSSv3: %0.1f)" % (host['ip'], vuln['port'], vuln['pluginID'], vuln['pluginName'], cvss, cvss3))
                    results.add(host['ip']+':'+vuln['port'])
                    r2.add((host['ip'], vuln["port"], vuln['pluginName'] + f"{vuln['pluginID']}", cvss, cvss3))
                except:
                    continue
        if self.verbose:
                self.display(["IP", "Port", "Vulnerability (PluginID)", "CVSS v2", "CVSS v3"], sorted(r2))
        return results

    def find_by_ips_ports(self, ips, ports, fullinfo=False):
        r"""find_by_ips_ports(["127.0.0.1", "192.168.0.1"], ["22", "80"]) -> set
        Search for vulnerabilities impacting ips addresses and their ports.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """

        if type(ips) is not list:
            ips = ips.split()
        if type(ports) is not list:
            ports = str(ports).split()
        results = list()
        for ip in ips:
            for port in ports:
                results.extend(self.find_by_ip_port(ip, port, fullinfo))
        results = set(results)
        return results

    def find_by_ip_port(self, ip, port, fullinfo=False):
        r"""find_by_ip_port("127.0.0.1", "22") -> set
        Search for vulnerabilities impacting ip address and his port.

        Returns:
            A collection containing all ip addresses and ports,
            or an empty collection if no address is found.
        """
        if type(port) == int:
            port = str(port)
        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            if host['ip'] == ip:
                vulns = host['report_items']
        for vuln in vulns:
            if vuln['port'] == port:
                if fullinfo == True:
                    self._all_info(host, vuln)
                results.add(ip+":"+vuln['port'])
                r2.add((host['ip'], vuln["port"], vuln['pluginName'], vuln['pluginID']))
        if self.verbose:
                self.display(["IP", "Port", "Vulnerability", "PluginID"], sorted(r2))
        return results

    def print_raw(self):
        r"""print_raw -> None
        Displays the raw data on the standard output.

        The logger must be in "INFO" mode, for display on the standard output.
        """

        if self._results:
            print(self._results)
        else:
            print("No information available")

    #TODO: Print table isn't very readable
    def find_all_cve(self, updatedb=False):
        r"""find_all_cve(updatedb=False) -> dict
            Search all cve contained in the.nessus file

            When the logger is in "INFO" mode, the ips addresses are displayed on the standard output.

            Returns:
                A collection containing all cve with plugin name,
                or an empty collection if no cve is found.
        """
        from pyExploitDb import PyExploitDb
        pEdb = PyExploitDb()
        pEdb.debug = False
        pEdb.autoUpdate = updatedb
        pEdb.openFile()
        results = dict()
        r2 = set()
        exploit = {}
        exploit_codes = {}
        already_printed = []
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                if len(vuln['cve']) > 0:
                    for cve in vuln['cve']:
                        if not cve in already_printed:
                            # CVE printed by PyExploitedDb :(
                            sys.stdout = open(os.devnull, 'w')
                            s = pEdb.searchCve(cve)
                            sys.stdout = sys.__stdout__
                            """
                            {'edbid': '41987', 'exploit': '/home/neko/.virtualenvs/ParserAndReplayer/lib/python3.6/site-packages/pyExploitDb/exploit-database/exploits/windows_x86-64/remote/41987.py',
                            'date': '2017-05-10', 'author': 'Juan Sacco', 'platform': 'remote', 'type': 'windows_x86-64', 'port': ''}
                            """
                            if type(s) is not dict:
                                s = {"exploit":''}
                            exploit_codes[cve] = s['exploit']
                            already_printed.append(cve)
                    exploit = exploit_codes
                    exploit_codes = {}
                    if len(exploit) > 0:
                        results[vuln['pluginName']] = exploit
                        
                            
                    
                    #r2.add((vuln['pluginName'], str(exploit)))
        #if self.verbose:
        #        self.display(["Vulnerability", "Exploit"], sorted(r2))
        # convert to json to avoid simple quote
        return json.loads(json.dumps(results))

    def find_all_vuln_name(self, fullinfo=False):
        r"""find_all_vuln_name() -> set
        Search all vulnerabilities contained in the.nessus file

        When the logger is in "INFO" mode, the ips addresses are displayed on the standard output.

        Returns:
            A collection containing all vulnerability name,
            or an empty collection if no vulnerability is found.
        """

        results = set()
        r2 = set()
        for host in self._results['report']['report_host']:
            for vuln in host['report_items']:
                if fullinfo == True:
                    print(host['ip'], vuln)
                results.add(vuln['pluginName'])
                r2.add((vuln["pluginName"], vuln['pluginID']))

        if self.verbose:
            self.display(["Vulnerability", "PluginID"], r2)

        return results

    def print_target_with_ports(self):
        results = set()
        for hosts in self._results['report']['report_host']:
            for vulns in hosts['report_items']:
                if vulns['port'] != "0":
                    results.add((hosts['ip'],int(vulns['port']), vulns['svc_name']))
            self.display(["IP", "Port", "Service"], sorted(results))
            results = set()

            
    def print_targets(self, fullinfo=False, delim="|"):
        r"""print_targets(False, ";") -> None
        Displays all ip addresses present info parsed reports

        """
        results = set()
        for host in self._results['report']['report_host']:
            info = {
                'scan_start':        '',
                'scan_stop':         '',
                'os':                '',
                'hostname':          'N/A',
                'netbios_name':      'N/A',
                'mac_address':       'N/A'
            }

            for tag in host['host_properties']['tags']:
                if tag['name'] == "HOST_START":
                    info['scan_start'] = tag['value']
                if tag['name'] == "HOST_END":
                    info['scan_stop'] = tag['value']
                if tag['name'] == "host-fqdn":
                    info['hostname'] = tag['value']
                if tag['name'] == "os":
                    info['os'] = tag['value']
                if tag['name'] == "netbios-name":
                    info['netbios_name'] = tag['value']
                if tag['name'] == "mac-address":
                    info['mac_address'] = tag['value']

            if fullinfo == True:
                print('ip:%s%snetbios:%s%sos:%s%sscan_start:%s%sscan_end:%s%smac_address:%s' % (host['ip'], delim,
                                            info['netbios_name'], delim,
                                            info['os'], delim,
                                            info['scan_start'], delim,
                                            info['scan_stop'], delim,
                                            info['mac_address']))
            results.add((host['ip'], info['hostname']))
        self.display(["IP", "Hostname"], results)

    def print_statistics(self):
        r"""
        Print statistics about parsed reports
        """
        vuln_low = 0
        vuln_med = 0
        vuln_high = 0
        vuln_info = 0
        vuln_local = 0
        vuln_local_uniq = []
        vuln_low_uniq = []
        vuln_med_uniq = []
        vuln_high_uniq = []
        vuln_info_uniq = []
        exploits = 0
        exploits_uniq = []

        targets = {}

        for host in self._results['report']['report_host']:
            targets[host['ip']] = {
                'vuln_low': 0,
                'vuln_med': 0,
                'vuln_high': 0,
                'vuln_info': 0,
                'vuln_local': 0,
                'vuln_local_uniq': [],
                'vuln_low_uniq': [],
                'vuln_med_uniq': [],
                'vuln_high_uniq': [],
                'vuln_info_uniq': [],
                'exploits': 0,
                'exploits_uniq': [],
            }

            for vuln in host['report_items']:
                # Check for CVSS score
                try:
                    cvss = float(vuln['cvss_base_score'])
                except:
                    continue
                if cvss <= 3.9:
                    if cvss == 0:

                        vuln_info += 1
                        targets[host['ip']]['vuln_info'] += 1
                        # Add uniq vuln (global)
                        if vuln['pluginID'] not in vuln_info_uniq:
                            vuln_info_uniq.append(vuln['pluginID'])
                        # Add uniq vuln (host)
                        if vuln['pluginID'] not in targets[host['ip']]['vuln_info_uniq']:
                            targets[host['ip']]['vuln_info_uniq'].append(vuln['pluginID'])
                    else:
                        vuln_low += 1
                        targets[host['ip']]['vuln_low'] += 1
                        # Add uniq vuln (global)
                        if vuln['pluginID'] not in vuln_low_uniq:
                            vuln_low_uniq.append(vuln['pluginID'])
                        # Add uniq vuln (host)
                        if vuln['pluginID'] not in targets[host['ip']]['vuln_low_uniq']:
                            targets[host['ip']]['vuln_low_uniq'].append(vuln['pluginID'])
                elif cvss >= 7.0:
                    vuln_high += 1
                    targets[host['ip']]['vuln_high'] += 1
                    # Add uniq vuln (global)
                    if vuln['pluginID'] not in vuln_high_uniq:
                        vuln_high_uniq.append(vuln['pluginID'])
                    # Add uniq vuln (host)
                    if vuln['pluginID'] not in targets[host['ip']]['vuln_high_uniq']:
                        targets[host['ip']]['vuln_high_uniq'].append(vuln['pluginID'])
                else:
                    vuln_med += 1
                    targets[host['ip']]['vuln_med'] += 1
                    # Add uniq vuln (global)
                    if vuln['pluginID'] not in vuln_med_uniq:
                        vuln_med_uniq.append(vuln['pluginID'])
                    # Add uniq vuln (host)
                    if vuln['pluginID'] not in targets[host['ip']]['vuln_med_uniq']:
                        targets[host['ip']]['vuln_med_uniq'].append(vuln['pluginID'])
                # Check local assessment vulnerabilities
                if vuln['plugin_type'] == self._LOCAL:
                    vuln_local += 1
                    # Add uniq local vulnerability (global)
                    if vuln['pluginID'] not in vuln_local_uniq:
                        vuln_local_uniq.append(vuln['pluginID'])
                    # Add uniq local vulnerability (host)
                    targets[host['ip']]['vuln_local'] += 1
                    if vuln['pluginID'] not in targets[host['ip']]['vuln_local_uniq']:
                        targets[host['ip']]['vuln_local_uniq'].append(vuln['pluginID'])
                # Check for public exploit availability
                if vuln['exploit_available'] == "true" or vuln['metasploit'] == "true":
                    exploits += 1
                    # Add uniq exploit (global)
                    if vuln['pluginID'] not in exploits_uniq:
                        exploits_uniq.append(vuln['pluginID'])
                    # Add uniq exploit (host)
                    targets[host['ip']]['exploits'] += 1
                    if vuln['pluginID'] not in targets[host['ip']]['exploits_uniq']:
                        targets[host['ip']]['exploits_uniq'].append(vuln['pluginID'])

        print("")
        print("#" * 8 + "  STATISTICS  " + "#" * 8)
        print("")
        print("Total targets:\t\t%d" % len(targets.keys()))
        print("Total vulns:\t\t%d\t[  unique:   %4d  ]" % (
        (vuln_high + vuln_med + vuln_low + vuln_info), len(vuln_high_uniq) \
        + len(vuln_med_uniq) + len(vuln_low_uniq) + len(vuln_info_uniq)))
        print("High vulns: \t\t%d\t[  unique: %6d  ]" % (vuln_high, len(vuln_high_uniq)))
        print("Medium vulns\t\t%d\t[  unique: %6d  ]" % (vuln_med, len(vuln_med_uniq)))
        print("Low vulns:\t\t%d\t[  unique: %6d  ]" % (vuln_low, len(vuln_low_uniq)))
        print("Info vulns:\t\t%d\t[  unique: %6d  ]" % (vuln_info, len(vuln_info_uniq)))
        print("Local vulns:\t\t%d\t[  unique: %6d  ]" % (vuln_local, len(vuln_local_uniq)))
        print("Available exploits:\t%d\t[  unique: %6d  ]" % (exploits, len(exploits_uniq)))
        print("Blacklist's size:\t%d\t[  filtered: %4d  ]" % (len(self._blacklist), self._blacklist_hit))

        print("")
        print("#" * 8 + "    TARGETS   " + "#" * 8)
        print("")

        for host in targets.keys():
            print("[*] %s" % host)
            total_vulns = targets[host]['vuln_high'] + targets[host]['vuln_med'] + targets[host]['vuln_low'] + \
                          targets[host]['vuln_info']
            total_vulns_uniq = len(targets[host]['vuln_high_uniq']) + len(targets[host]['vuln_med_uniq']) + len(
                targets[host]['vuln_low_uniq']) \
                               + len(targets[host]['vuln_info_uniq'])
            print("\tTotal vulns: \t\t%d\t[  unique: %6d  ]" % (total_vulns, total_vulns_uniq))
            print("\t  [+] Local vulns:\t%d\t[  unique: %6d  ]" % (
            targets[host]['vuln_local'], len(targets[host]['vuln_local_uniq'])))
            print("\t  [+] Remote vulns:\t%d\t[  unique: %6d  ]" % (total_vulns - targets[host]['vuln_local'],
                                                                    total_vulns_uniq - len(
                                                                        targets[host]['vuln_local_uniq'])))
            print("\tHigh vulns: \t\t%d\t[  unique: %6d  ]" % (
            targets[host]['vuln_high'], len(targets[host]['vuln_high_uniq'])))
            print("\tMedium vulns\t\t%d\t[  unique: %6d  ]" % (
            targets[host]['vuln_med'], len(targets[host]['vuln_med_uniq'])))
            print("\tLow vulns:\t\t%d\t[  unique: %6d  ]" % (targets[host]['vuln_low'], len(targets[host]['vuln_low_uniq'])))
            print("\tInfo vulns:\t\t%d\t[  unique: %6d  ]" % (
            targets[host]['vuln_info'], len(targets[host]['vuln_info_uniq'])))
            print("\tAvailable exploits:\t%d\t[  unique: %6d  ]" % (
            targets[host]['exploits'], len(targets[host]['exploits_uniq'])))

    def find_interesting_vulns(self, fullinfo=False):
        vulns = importlib.resources.read_text("ParserAndReplayer.extra", 'interesting_vulnerabilities.txt').split('\n')
        self.find_by_pluginNames(fullinfo, *vulns)
