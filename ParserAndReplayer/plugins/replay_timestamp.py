from ParserAndReplayer.replay import RunExternalTool
from ParserAndReplayer.config.config import hping, icmpquery

class ReplayTimestamp(RunExternalTool):
    def __init__(self, ips, output_path='/timestamp'):
        self.ips = ips
        super(ReplayTimestamp, self).__init__(self.ips, output_path)


    def prepare_tcp(self):
        ips = []
        for ip in self.ips:
            ips.append(ip.replace(":", " -p "))
        self._clear_queue()
        for ip in ips:
            self.m.queue.put(ip)
        return ips


    def prepare_icmp(self):
        ips = []
        for ip in self.ips:
            ips.append(ip.split(":")[0])
        self._clear_queue()
        for ip in ips:
            self.m.queue.put(ip)
        return ips


    def run_hping_icmp(self, hping_options="-c 5 --icmp --icmp-ts", extrapath="-icmp-timestamp"):
        self.ips = self.prepare_icmp()
        self._run(hping, None, hping_options, extrapath)


    def run_hping_tcp(self, hping_options="-c 5 -S --tcp-timestamp", extrapath="-tcp-timestamp"):
        self.ips = self.prepare_tcp()
        self._run(hping, None, hping_options, extrapath)


    def run_icmpquery(self, icmpquery_options="-t", extrapath=''):
        self._run(icmpquery, None, icmpquery_options, extrapath)
