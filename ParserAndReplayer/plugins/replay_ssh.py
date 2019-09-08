from ParserAndReplayer.replay import RunExternalTool
from ParserAndReplayer.config.config import sshaudit

class ReplaySSH(RunExternalTool):
    def __init__(self, ips, output_path='/ssh'):
        super(ReplaySSH,self).__init__(ips, output_path)


    def run_sshaudit(self, sshaudit_options="", extrapath=""):
        self._run(sshaudit, None, sshaudit_options, extrapath)
