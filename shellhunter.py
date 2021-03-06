# !/usr/bin/python3

import argparse
from os import _exit

from src.scanner import scanner

__version__ = "1.1.0"


class ShellFinder():

    def __init__(self, version: str) -> None:
        """
        Parse user info to Scanner
        :param version:
        """
        self.parser = argparse.ArgumentParser()
        self.group = self.parser.add_mutually_exclusive_group(required=True)

        self.group.add_argument('--url', '-u', action='store', dest='URL', help='URL to scan', default=False)
        self.group.add_argument('--file', '-f', action='store', dest='File', help='Phishings URL file', default=False)

        self.parser.add_argument('--proxy', '-p', action='store', dest='proxy',
                                 help='proxy country to use ( look user_files/config.txt)', default=False)
        self.parser.add_argument('--shell-list', '-sf', action='store', dest='shellfile',
                                 help='Shell File, default: src/shell_list.lst', default="src/shell_list.lst")
        self.parser.add_argument('--save', '-s', action='store', dest='Save', help='Save to...', default=False)
        self.parser.add_argument('--threads', '-t', action='store', dest='threads', help='Threads to run, default 20',
                                 type=int, default=20)
        self.parser.add_argument('--hide-code', '-hc', action='store', dest='hidecode',
                                 help='Do not show responses w/ this code', nargs="+", type=int, default=[])
        self.parser.add_argument('--show-code', '-sc', action='store', dest='showonly',
                                 help='Do not show responses w/o this code', nargs="+", type=int, default=[200, 302])
        self.parser.add_argument('--show-string', '-ss', action='store', dest='string',
                                 help='show responses w/ this string', default=False)
        self.parser.add_argument('--hide-string', '-hs', action='store', dest='notstring',
                                 help='Do not show responses w/o this string', default=False)
        self.parser.add_argument('--show-regex', '-sr', action='store', dest='regex',
                                 help='Do not show responses w this regex', default=False)
        self.parser.add_argument('--hide-regex', '-hr', action='store', dest='notregex',
                                 help='Do not show responses w/o this regex', default=False)

        self.parser.add_argument('--greater-than', '-gt', action='store', dest='showChars',
                                 help='show responses with a number of characters greater than X', type=int,
                                 default=False)
        self.parser.add_argument('--smaller-than', '-st', action='store', dest='hideChars',
                                 help='Do not show responses with a number of characters greater than X', type=int,
                                 default=False)

        scanner(version,
                self.parser.parse_args()).start()  # scanner create Target object, which store all session options


if __name__ == "__main__":

    try:
        main = ShellFinder(__version__)

    except KeyboardInterrupt:
        print()
        print("bye")
        _exit(1)

    except Exception as e:
        print("\033[91m\nunexpected Exception:\033[0m " + str(e))
