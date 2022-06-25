from setuptools import setup, find_packages

print(find_packages())
setup(
    name='ParserAndReplayer',
    version='0.0.1',
    author='NekoSecurity',
    author_email='',
    description='Parse and replay traces',
    packages=find_packages(),
    include_package_data=True,
    package_data = {'ParserAndReplayer': ['lib/*.so', "extra/*"]},
    url='',
    scripts=["ParserAndReplayer/scripts/parser_and_replayer.py"],
    license='GPLv3',
    platforms=["Linux"],
    zip_safe=False,
    python_requires=">=3.7",
)
