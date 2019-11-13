# ParserAndReplayer v0.0.1
# Description
During Pentesting missions, it happens to launch Nessus to get an overview of the perimeter and quickly obtain vulnerable components with vulnerabilities that have been disclosed.   
However, it is not uncommon to have false positives and therefore you should not trust the tool 100%.

That's why I developed `ParserAndReplayer`. Originally, I used the parser of [Alessandro Di Pinto](https://github.com/adipinto/yet-another-nessus-parser), to which I added data extraction features and features to replay some traces.

However, when the .nessus file is large, the parsing of the file becomes very slow. That's why I developed a new *Rust* parser. It is strongly inspired by the work of [kpcyrd](https://github.com/kpcyrd/nessus-rs).   
I didn't use his project because it's not really adapted to my use. It does not get enough information from the nessus file and is focused on launching a nessus scan. 


This project is library oriented, but a script is provided for those who want to use it without developing. 

# Features
As the project name indicates, it is possible to analyze a Nessus scan but also to replay traces.

## Parser
As explained above, I added some new features to the existing one.

Below is a list of the features of the parser:
* def find_by_pluginID(self, pluginID, fullinfo=False)
* def find_by_pluginIDs(self, fullinfo=False, *pluginsIDS)
* def find_by_pluginName(self, pluginName, fullinfo=False)
* def find_by_pluginNames(self, fullinfo=False, *pluginNames)
* def find_by_severities(self, fullinfo=False, *severities)
* def find_by_severity(self, severity, fullinfo=False)
* def find_by_metasploit_exploitability(self, fullinfo=False)
* def find_by_canvas_exploitability(self, fullinfo=False)
* def find_by_nessus_exploitability(self, fullinfo=False)
* def find_by_core_exploitability(self, fullinfo=False)
* def find_by_ports(self, fullinfo=False, *ports)
* def find_by_port(self, port, fullinfo=False)
* def find_by_ips(self, fullinfo=False, *ips)
* def find_by_ip(self, ip, fullinfo=False)
* def find_by_cvss(self, cvss, fullinfo=False)
* def find_by_ips_ports(self, ips, ports, fullinfo=False)
* def find_by_ip_port(self, ip, port, fullinfo=False)
* def print_raw(self)
* def find_all_cve(self, updatedb=False)
* def find_all_vuln_name(self, fullinfo=False)
* def print_targets(self, fullinfo=False, delim="|")
* def print_statistics(self)

## Replayer
I tried to develop the modular replayer part, with a common base and add plugins by type of replay desired.

The `replay.py` file contains the basic code for replay. It is divided into two classes:
* RunInternalCode
* RunExternalCode

For `RunExternalCode`, the configuration file is installed here `$HOME/.config/ParserAndReplayer/ParserAndReplayer.conf`. This file contains the path of the tools you want to execute.


In addition, the replayer creates directories where the script is executed (ssh, banner, ssl, rdp, smb) and each directory contains a file with traces.

For example, the "plugin" folder currently contains:
* replay_banner.py
* replay_rdp.py
* replay_smb.py
* replay_ssh.py
* replay_ssl.py
* replay_timestamp.py

Below is the list of features:
* replay_banner.py
    * run_ftp
    * run_http
    * run_https
    * run_telnet
* replay_rdp.py
    * run_rdp_sec_check
    * run_rdp_check_ciphers
* replay_smb.py
    * run_show_smb_version (custom tool)
* replay_ssh.py
    * run_sshaudit
* replay_ssl.py
    * run_testssl (little buggy :()
    * run_sslscan
* replay_timestamp
    * run_hping_icmp
    * run_hping_tcp
    * run_icmpquery

# Installation
First of all, you have to compile the parser in Rust and copy the library into the lib folder of ParserAndReplayer.  
It is important to specify this library only works with **Python 3** 
```
cargo build --release
cp target/libneko_parser $PATH_OF_ParserAndReplayer/lib/neko_libparser.so
```

After that:
```
pip3 install -r requirements.txt
pip3 install .
```

# Update

```
git pull
```

# Usage
In order to take full advantage of the features offered by the library, it is necessary to modify the location of the different tools that will be used during replay.  
  
First, check the tool path in the `$HOME/.config/ParserAndReplayer/ParserAndReplayer.conf` file.

```python
from ParserAndReplayer.parser.nessus import Nessus
from ParserAndReplayer.plugins.replay_ssh import ReplaySSH
n = Nessus("file.nessus")
# First we update cve database
n.find_all_cve(updatedb=True)

# We list all vulnerabilities
vulns = nessus.find_all_vuln_name()

#ssh contains all ip:port in a set()
ssh = n.find_by_pluginName("SSH")
ReplaySSH(ssh).run_sshaudit()



print(n.find_by_pluginNames(fullinfo=True, "ssh", "ssl"))
```

If we use the `parser_and_replayer.py` script:
```bash
$ parser_and_replayer.py analyze --cve file.nessus
$ parser_and_replayer.py --verbose --fullinfo analize --pluginName SSH RDP file.nessus
```

# Extra
The extra folder contains a python script that I use for SMB

# References
[Yet Another Nessus Parser](https://github.com/adipinto/yet-another-nessus-parser)  
[Rust Nessus-rs](https://github.com/kpcyrd/nessus-rs)  
[Pwntools](https://github.com/Gallopsled/pwntools) for `log.py` file

# Issues
It is possible that it will be necessary to recompile the library in rust

# TODO
- [ ] Redesign plugins system  
- [ ] Add report fonctionnality  
- [ ] Rewrite replay_banner.py  
- [ ] Add another parser like nmap  
- [ ] Add replay in parser_and_replayer.py
