from ParserAndReplayer.replay import RunInternalCode


class ReplayBanner(RunInternalCode):
    def __init__(self, ips, output_path="/banner"):
        super(ReplayBanner, self).__init__(ips, output_path)

    def run_ftp(self, ssl=False, options="", extrapath=""):
        self._run("ftp", ssl, options, extrapath)

    def run_http(self, ssl=False, options="", extrapath=""):
        self._run("http", ssl, options, extrapath)

    def run_https(self, ssl=True, options="", extrapath=""):
        self._run("https", ssl, options, extrapath)

    def run_telnet(self, ssl=False, options="", extrapath=""):
        self._run("telnet", ssl, options, extrapath)
