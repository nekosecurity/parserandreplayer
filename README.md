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

Below is a complete list of the parser's features:
* Find by plugin id 
* Find by plugin name
* Find by severity
* Find by framework exploitability (Metasploit, Canvas, Nessus, Core Impact)
* Find by port
* Find by IP
* Find by CVSS
* Find by IP port
* Print raw data
* Find all CVE
* Find all vulnerabilities name
* Print all targets
* Print Dtatistics
* Find by list of interesting vulnerabilities

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
It is important to specify this library only works with **Python 3** 
```
make install
make clean
```

# Update

```
git pull
```

# Usage
In order to take full benefit of the features offered by the library, it's necessary to change all the tools locations that will be used during the replay.    
Check the configuration file `$HOME/.config/ParserAndReplayer/ParserAndReplayer.conf`.

## Usage as lib
```python
from ParserAndReplayer.parser.nessus import Nessus
from ParserAndReplayer.plugins.replay_ssh import ReplaySSH
n = Nessus("file.nessus")
# First we update cve database
n.find_all_cve(updatedb=True)

# We list all vulnerabilities
vulns = n.find_all_vuln_name()

#ssh contains all ip:port in a set()
ssh = n.find_by_pluginName("SSH")
ReplaySSH(ssh).run_sshaudit()



print(n.find_by_pluginNames(fullinfo=True, "ssh", "ssl"))
```

## Usage `parser_and_replayer.py` script
```bash
$ parser_and_replayer.py analyze --cve file.nessus
$ parser_and_replayer.py --verbose --fullinfo analyze --pluginName SSH RDP file.nessus
```

# Extra
The extra folder contains a python script that I use for SMB and a list of interesting vulnerabilities

# References
[Yet Another Nessus Parser](https://github.com/adipinto/yet-another-nessus-parser)  
[Rust Nessus-rs](https://github.com/kpcyrd/nessus-rs)  
[Pwntools](https://github.com/Gallopsled/pwntools) for `log.py` file

# TODO
- [ ] Redesign plugins system  
- [ ] Add report fonctionnality  
- [ ] Rewrite replay_banner.py  
- [ ] Add another parser like nmap  
- [ ] Add replay in parser_and_replayer.py
