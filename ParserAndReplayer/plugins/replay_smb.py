from ParserAndReplayer.replay import RunExternalTool
from ParserAndReplayer.config.config import show_smb_version


class ReplaySMB(RunExternalTool):
    def __init__(self, ips, output_path="/smb"):
        super(ReplaySMB, self).__init__(ips, output_path)

    def run_show_smb_version(self, smb_version="1", extrapath=""):
        smb_version = "--dialect " + smb_version
        self._run(show_smb_version, None, smb_version, extrapath)
