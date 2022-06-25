from setuptools import setup, find_packages

PACKAGE_NAME="ParserAndReplayer"

setup(
    name='ParserAndReplayer',
    version='0.0.1',
    packages=["ParserAndReplayer", "ParserAndReplayer.config",
              "ParserAndReplayer.lib",
              "ParserAndReplayer.parser", "ParserAndReplayer.plugins",
              "ParserAndReplayer.helpers", "ParserAndReplayer.extra"
            ],
    url='',
    scripts=["ParserAndReplayer/scripts/parser_and_replayer.py"],
    data_files=["ParserAndReplayer/lib/neko_libparser.so", "ParserAndReplayer/config/ParserAndReplayer.conf",
               'ParserAndReplayer/extra/interesting_vulnerabilities.txt'],
    license='GPLv3',
    author='NekoSecurity',
    author_email='',
    description='Parse and replay traces',
    maintainer="NekoSecurity",
    maintainer_email='',
    platforms=["Linux"],
    include_package_data=True,
    zip_safe=False
)
