# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from ParserAndReplayer.log import *
from os import mkdir, chdir
from os.path import exists, basename
from ParserAndReplayer.config.config import output_dir
from subprocess import Popen, PIPE
from multiprocessing import Process, Queue, Manager, Lock, Pool
from abc import ABCMeta, abstractmethod
import ssl as ssl_library
import socket
import queue # imported for using queue.Empty exception
import shlex


class PluginBase(object):
    __metaclass__ = ABCMeta

    def __init__(self, ips, output_path, max_process=10):
        self.output_path = output_dir+output_path
        if not exists(self.output_path):
            mkdir(self.output_path)
            rootlogger.info("%s directory created" % (self.output_path))
        chdir(self.output_path)
        self.ips = ips
        if len(self.ips) > 10:
            self.max_process = max_process
        else:
            self.max_process = len(self.ips)
        self.m = Manager()
        self.m.queue = Queue()
        for ip in self.ips:
            self.m.queue.put(ip)

    @abstractmethod
    def _run_cmd(self, ips, tool, options="", extraname=""):
        raise NotImplementedError

    @abstractmethod
    def _run(self, tool, ssl, options, extraname=""):
        raise NotImplementedError

    def write_file(self, name, mode="wb", tool="", extraname="", data=""):
        r""" write_file("test", "wb", "hping", "ssl")
            Write the result of the commands in a file

        """
        rootlogger.info("Writing result in file")
        name = name + basename(tool) + extraname + ".txt"
        with open(name, mode) as f:
            f.write(data)
            f.write(b"\n")
        #rootlogger.info("%s finished on %s " % (tool, ip))


class RunExternalTool(PluginBase):
    def __init__(self, ips, output_path):
        super(RunExternalTool, self).__init__(ips, output_path)

    def _run_cmd(self, ips, tool, ssl=None, options="", extraname=""):
        r"""
            Launches an external program
        """

        while True:
            try:
                if ips.empty():
                    break
                ip = ips.get()
                rootlogger.info("%s performed on %s" % (basename(tool), ip))
                print(tool, options, ip)
                if len(options) == 0:
                    process = Popen([tool, ip], stdout=PIPE, stderr=PIPE)
                else:
                    cmd = tool + " " + options + " " + ip
                    cmd = shlex.split(cmd)
                    #process = Popen([tool, options, ip], stdout=PIPE, stderr=PIPE)
                    process = Popen(cmd, stdout=PIPE, stderr=PIPE)

                res = process.communicate()
                print(res)
                process.wait()
                # clean ip for tcp-timestamp
                ip = ip.replace(" -p ", ":")
                self.write_file(ip+"_", tool=basename(tool).split(".")[0], extraname=extraname, data=res[0])
            except queue.Empty:
                print('except')
                break



    def _run(self, tool, ssl="", options="", extraname=""):
        r""" _run(rdp_sec_check, rdp_option, extrapath)
            Allows to execute external commands, creating one process per program
        """
        print(self.max_process)
        for _ in range(0, self.max_process):
            p = Process(target=self._run_cmd, args=(self.m.queue, tool, ssl, options, extraname))
            p.daemon=True
            p.start()
            p.join()


    def _clear_queue(self):
        while not self.m.queue.empty():
            self.m.queue.get()


class RunInternalCode(PluginBase):
    def __init__(self, ips, output_path):
        super(RunInternalCode, self).__init__(ips, output_path)


    def _run_cmd(self, ips, tool=None, ssl=False, options="", extraname=""):
        r"""
        Use sockets to retrieve banners
        """
        while True:
            try:
                ip = ips.get_nowait()
                ip, port = ip.split(":")
                rootlogger.info("%s performed on %s" % (basename(tool), ip))
                s = socket.socket()
                s.connect((ip, int(port)))
                recv = ""
                try:
                    if ssl is True:
                        try:
                            context = ssl_library.create_default_context()
                            context = ssl_library.SSLContext(ssl_library.PROTOCOL_TLS)
                            context.verify_mode = ssl_library.CERT_NONE
                            context.check_hostname = False
                            s = context.wrap_socket(s)
                        except ssl_library.SSLError as e:
                           print("error: %s" % e)


                    if tool == "http" or tool == "https":

                        s.sendall(b"HEAD / HTTP/1.1\r\nHost:"+ip.encode()+b"\r\n\r\n")
                        #print(ip.decode())
                        recv = s.recv(1024)
                        s.close()
                    else:
                        socket.setdefaulttimeout(5)
                        recv = s.recv(1024)
                    if len(recv) > 0:
                        self.write_file(ip+":"+port+"_", tool=tool, extraname=extraname, data=recv)
                    rootlogger.info("%s finished on %s " % (tool, ip))
                except EOFError as e:
                    rootlogger.warning("error: %s" % e)
            except queue.Empty:
                break

    def _run(self, tool, ssl, options, extraname=""):
        r""" _run("ftp", ssl=False, extrapath)
            Allows to execute python code, creating one process per execution
        """
        for _ in range(self.max_process):
            p = Process(target=self._run_cmd, args=(self.m.queue, tool, ssl, options, extraname))
            p.daemon=True
            p.start()
            p.join()
