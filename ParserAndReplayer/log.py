import logging
import colorama
import sys

__all__ = [
    'getLogger', 'install_default_handler', 'rootlogger'
]

colorama.init()

_msgtype_prefixes = {
    'status'       : [colorama.Fore.LIGHTMAGENTA_EX, 'x'],
    'success'      : [colorama.Fore.LIGHTGREEN_EX, '+'],
    'failure'      : [colorama.Fore.LIGHTRED_EX, '-'],
    'debug'        : [colorama.Fore.LIGHTRED_EX, 'DEBUG'],
    'info'         : [colorama.Fore.LIGHTBLUE_EX, '*'],
    'warning'      : [colorama.Fore.LIGHTYELLOW_EX, '!'],
    'error'        : [colorama.Back.RED, 'ERROR'],
    'exception'    : [colorama.Back.RED, 'ERROR'],
    'critical'     : [colorama.Back.RED, 'CRITICAL'],
    'info_once'    : [colorama.Fore.LIGHTBLUE_EX, '*'],
    'warning_once' : [colorama.Fore.LIGHTYELLOW_EX, '!'],
    }


class Logger:
    _one_time_infos    = set()
    _one_time_warnings = set()

    def __init__(self, logger=None):
        self.level_name = {"INFO": logging.INFO,
                           "DEBUG":logging.DEBUG,
                           "ERROR":logging.ERROR,
                           "WARNING": logging.WARNING
                           }
        if logger is None:
            module = self.__module__
            module = "ParserAndReplayer." + module
            logger_name = '%s.%s.%s' % (module, self.__class__.__name__, id(self))
            logger = logging.getLogger(logger_name)
            logger.setLevel(1)
        self._logger = logger

    def _getLevel(self, level):
        if isinstance(level,int):
            return level
        return self.level_name[level.upper()]

    def _log(self, level, msg, args, kwargs, msgtype, progress=None):
        extra = kwargs.get('extra', {})
        extra.setdefault('ParserAndReplayer', msgtype)
        extra.setdefault('ParserAndReplayer', progress)
        kwargs['extra'] = extra
        return self._logger.log(level, msg, *args, **kwargs)


    def indented(self, message, *args, **kwargs):
        """indented(message, *args, level = logging.INFO, **kwargs)

        Log a message but don't put a line prefix on it.

        Arguments:
            level(int): Alternate log level at which to set the indented
                        message.  Defaults to :const:`logging.INFO`.
        """
        level = self._getLevel(kwargs.pop('level', logging.INFO))
        self._log(level, message, args, kwargs, 'indented')

    def success(self, message, *args, **kwargs):
        self._log(logging.INFO, message, args, kwargs, 'success')

    def failure(self, message, *args, **kwargs):
        self._log(logging.INFO, message, args, kwargs, 'failure')

    def info_once(self, message, *args, **kwargs):
        """info_once(message, *args, **kwargs)

        Logs an info message.  The same message is never printed again.
        """
        m = message % args
        if m not in self._one_time_infos:
            if self.isEnabledFor(logging.INFO):
                self._one_time_infos.add(m)
            self._log(logging.INFO, message, args, kwargs, 'info_once')

    def warning_once(self, message, *args, **kwargs):
        """warning_once(message, *args, **kwargs)

        Logs a warning message.  The same message is never printed again.
        """
        m = message % args
        if m not in self._one_time_warnings:
            if self.isEnabledFor(logging.INFO):
                self._one_time_warnings.add(m)
            self._log(logging.WARNING, message, args, kwargs, 'warning_once')

    def warn_once(self, *args, **kwargs):
        """Alias for :meth:`warning_once`."""
        return self.warning_once(*args, **kwargs)

    # logging functions also exposed by `logging.Logger`

    def debug(self, message, *args, **kwargs):
        """debug(message, *args, **kwargs)

        Logs a debug message.
        """
        self._log(logging.DEBUG, message, args, kwargs, 'debug')

    def info(self, message, *args, **kwargs):
        """info(message, *args, **kwargs)

        Logs an info message.
        """
        self._log(logging.INFO, message, args, kwargs, 'info')

    def warning(self, message, *args, **kwargs):
        """warning(message, *args, **kwargs)

        Logs a warning message.
        """
        self._log(logging.WARNING, message, args, kwargs, 'warning')

    def warn(self, *args, **kwargs):
        """Alias for :meth:`warning`."""
        return self.warning(*args, **kwargs)

    def error(self, message, *args, **kwargs):
        """error(message, *args, **kwargs)

        To be called outside an exception handler.

        Logs an error message, then raises a ``PwnlibException``.
        """
        self._log(logging.ERROR, message, args, kwargs, 'error')
        raise Exception(message % args)

    def exception(self, message, *args, **kwargs):
        """exception(message, *args, **kwargs)

        To be called from an exception handler.

        Logs a error message, then re-raises the current exception.
        """
        kwargs["exc_info"] = 1
        self._log(logging.ERROR, message, args, kwargs, 'exception')
        raise Exception

    def critical(self, message, *args, **kwargs):
        """critical(message, *args, **kwargs)

        Logs a critical message.
        """
        self._log(logging.CRITICAL, message, args, kwargs, 'critical')

    def log(self, level, message, *args, **kwargs):
        """log(level, message, *args, **kwargs)

        Logs a message with log level `level`.  The ``ParserAndReplayer`` formatter will
        use the default :mod:`logging` formater to format this message.
               """
        self._log(level, message, args, kwargs, None)

    def isEnabledFor(self, level):
        """isEnabledFor(level) -> bool

        See if the underlying logger is enabled for the specified level.
        """
        effectiveLevel = self._logger.getEffectiveLevel()

        if effectiveLevel == 1:
            effectiveLevel = level
        return effectiveLevel <= level

    def setLevel(self, level):
        """setLevel(level)

        Set the logging level for the underlying logger.
        """
        if isinstance(level, int):
            self._logger.setLevel(level)
        else:
            self._logger.setLevel(self.level_name[level.upper()])
    def addHandler(self, handler):
        """addHandler(handler)

        Add the specified handler to the underlying logger.
        """
        self._logger.addHandler(handler)

    def removeHandler(self, handler):
        """removeHandler(handler)

        Remove the specified handler from the underlying logger.
        """
        self._logger.removeHandler(handler)

    @property
    def level(self):
        return self._logger.level
    @level.setter
    def level(self, value):
            self._logger.level = value


class _devnull(object):
    name = None
    def write(self, *a, **kw): pass
    def read(self, *a, **kw):  return ''
    def flush(self, *a, **kw): pass
    def close(self, *a, **kw): pass

class LogfileHandler(logging.FileHandler):
    def __init__(self):
        super(LogfileHandler, self).__init__('', delay=1)

    @property
    def stream(self):
        return _devnull()

    @stream.setter
    def stream(self, value):
        pass

    def handle(self, *a, **kw):
        if self.stream.name is not None:
            super(LogfileHandler, self).handle(*a, **kw)

class Formatter(logging.Formatter):
    """
    Logging formatter which performs custom formatting for log records
    containing the ``'ParserAndReplayer_msgtype'`` attribute.  Other records are formatted
    using the `logging` modules default formatter.

    If ``'ParserAndReplayer_msgtype'`` is set, it performs the following actions:

    * A prefix looked up in `_msgtype_prefixes` is prepended to the message.
    * The message is prefixed such that it starts on column four.
    * If the message spans multiple lines they are split, and all subsequent
      lines are indented.

    This formatter is used by the handler installed on the ``'ParserAndReplayer'`` logger.
    """

    # Indentation from the left side of the terminal.
    # All log messages will be indented at list this far.
    indent = '    '

    # Newline, followed by an indent.  Used to wrap multiple lines.
    nlindent = '\n' + indent

    def format(self, record):
        # use the default formatter to actually format the record
        msg = super(Formatter, self).format(record)

        # then put on a prefix symbol according to the message type
        msgtype = getattr(record, 'ParserAndReplayer_msgtype', None)
        # if 'ParserAndReplayer_msgtype' is not set (or set to `None`) we just return the
        # message as it is
        if msgtype is None:
            return msg

        if msgtype in _msgtype_prefixes:
            style, symb = _msgtype_prefixes[msgtype]
            prefix = '[%s] ' % (style+symb+colorama.Style.RESET_ALL)
        elif msgtype == 'indented':
            prefix = self.indent
        elif msgtype == 'animated':
            # the handler will take care of updating the spinner, so we will
            # not include it here
            prefix = ''
        else:
            # this should never happen
            prefix = '[?] '

        msg = prefix + msg
        msg = self.nlindent.join(msg.splitlines())
        return msg

def getLogger(name):
    return Logger(logging.getLogger(name))


class Handler(logging.StreamHandler):
    """
    A custom handler class.  This class will report whatever
    :data:`context.log_level` is currently set to as its log level.

    If :data:`term.term_mode` is enabled log records originating from a progress
    logger will not be emitted but rather an animated progress line will be
    created.

    An instance of this handler is added to the ``'ParserAndReplayer'`` logger.
    """

    @property
    def stream(self):
        return sys.stdout

    @stream.setter
    def stream(self, value):
        pass

    def emit(self, record):
        """
        Emit a log record or create/update an animated progress logger
        depending on whether :data:`term.term_mode` is enabled.
        """
        # We have set the root 'ParserAndReplayer' logger to have a logLevel of 1,
        # when logging has been enabled via install_default_handler.
        #
        # If the level is 1, we should only process the record if
        # context.log_level is less than the record's log level.
        #
        # If the level is not 1, somebody else expressly set the log
        # level somewhere on the tree, and we should use that value.
        level = logging.getLogger(record.name).getEffectiveLevel()
        if level == 1:
            level = logging.INFO
        if level > record.levelno:
            return

        progress = getattr(record, 'ParserAndReplayer_progress', None)
        # if the record originates from a `Progress` object and term handling
        # is enabled we can have animated spinners! so check that

        if progress is None:
            super(Handler, self).emit(record)
            return

            # yay, spinners!

            # since we want to be able to update the spinner we overwrite the
            # message type so that the formatter doesn't output a prefix symbol
        #msgtype = record.ParserAndReplayer_msgtype
        record.ParserAndReplayer_msgtype = 'animated'
        #msg = "%s\n" % self.format(record)


iso_8601 = '%Y-%m-%dT%H:%M:%S'
fmt = '%(asctime)s:%(levelname)s:%(name)s:%(message)s'
log_file = LogfileHandler()
log_file.setFormatter(logging.Formatter(fmt, iso_8601))

rootlogger = getLogger('Nessus Parser')
console = Handler()
formatter = Formatter()
console.setFormatter(formatter)
rootlogger.addHandler(console)
rootlogger.setLevel(1)

def install_default_handler():
    logger = logging.getLogger('Nessus Parser')

    if console not in logger.handlers:
        logger.addHandler(console)
        logger.addHandler(log_file)

    logger.setLevel(1)
