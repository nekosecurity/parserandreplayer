# -*- coding: utf-8 -*-
from ParserAndReplayer.replay import RunExternalTool
from ParserAndReplayer.config.config import sslscan, testssl

class ReplaySSL(RunExternalTool):
    def __init__(self, ips, output_path="/ssl"):
        super(ReplaySSL, self).__init__(ips, output_path)


    def run_sslscan(self, sslscan_options="", extrapath=""):
        self._run(sslscan, sslscan_options, extrapath)

    #TODO testssl bug when it takes time to finish, which causes a process that runs indefinitely
    def run_testssl(self, testssl_options="", extrapath=""):
        self._run(testssl,  None, testssl_options, extrapath)