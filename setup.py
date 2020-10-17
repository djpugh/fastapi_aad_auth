#!/usr/bin/env python
"""
Setup script for fastapi_aad_auth
=================================

Call from command line as::

    python setup.py --help

to see the options available.
"""
from setuptools import setup
from setuptools.config import read_configuration
from pkg_resources import parse_version, parse_requirements

try:
    import versioneer
    __version__ = versioneer.get_version()
    cmdclass = versioneer.get_cmdclass()
except AttributeError:
    __version__ = '0.0.0'
    cmdclass = None


# We are going to take the approach that the requirements.txt specifies
# exact (pinned versions) to use but install_requires should only
# specify package names
# see https://caremad.io/posts/2013/07/setup-vs-requirement/
# install_requires should specify abstract requirements e.g.::
#
#   install_requires = ['requests']
#
# whereas the requirements.txt file should specify pinned versions to
# generate a repeatable environment

with open('requirements.txt') as f:
    install_requires = []
    for req in parse_requirements(f.read()):
        install_requires.append(str(req).replace('==', '>='))

if parse_version(__version__) < parse_version('0.2.0'):
    development_status = 'Development Status :: 2 - Pre-Alpha'
elif parse_version(__version__).is_prerelease :
    development_status = 'Development Status :: 4 - Beta'
elif parse_version(__version__) >= parse_version('0.2.0'):
    development_status = 'Development Status :: 5 - Production/Stable'
elif parse_version(__version__) >= parse_version('1.0.0'):
    development_status = 'Development Status :: 6 - Mature'
else:
    development_status = 'Development Status :: 1 - Planning'

config = read_configuration('setup.cfg')
# See https://pypi.org/classifiers/
classifiers = config['metadata']['classifiers']
classifiers.append(development_status)

kwargs = {'install_requires': install_requires,
          'version':  __version__,
          'classifiers': classifiers}


if cmdclass is not None:
    kwargs['cmdclass'] = cmdclass

if __name__ == "__main__":
    setup(**kwargs)