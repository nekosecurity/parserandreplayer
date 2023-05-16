from ParserAndReplayer.replay import RunExternalTool
from ParserAndReplayer.config.config import rdp_sec_check, rdp_check_ciphers


class ReplayRDP(RunExternalTool):
    def __init__(self, ips, output_path="/rdp"):
        super(ReplayRDP, self).__init__(ips, output_path)

    def run_rdp_check_sec(self, rdp_options, extrapath=""):
        self._run(rdp_sec_check, rdp_options, extrapath)

    def run_rdp_check_ciphers(self, rdp_options, extrapath=""):
        self._run(rdp_check_ciphers, rdp_options, extrapath)
