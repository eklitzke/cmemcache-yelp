#!/usr/bin/env python

"""
Install script for cmemcache extension.
"""

__author__ = "Gijsbert de Haan <gijsbert.de.haan@gmail.com>"

from distutils.core import setup, Extension
import sys
from glob import glob

def read_version():
    try:
        return open('VERSION', 'r').readline().strip()
    except IOError, e:
        raise SystemExit(
            "Error: you must run setup from the root directory (%s)" % str(e))

sources = glob("*.c")
undefine = []
define = []

try:
    sys.argv.remove("--debug")
    undefine.append("NDEBUG")
    define.append(("DEBUG", 1))
except ValueError:
    pass

# This assumes that libmemcache is installed with base /usr/local
cmemcache = Extension(
    "_cmemcache",
    sources,
    include_dirs = ['/usr/local/include'],
    extra_compile_args = ['-Wall'],
    libraries=['memcache'],
    library_dirs=['/usr/local/lib'],
    extra_link_args=['--no-undefined', '-Wl,-rpath=/usr/local/lib'],
    define_macros=define,
    undef_macros=undefine)

setup(name="cmemcache",
      version=read_version(),
      description="cmemcache -- memcached extension",
      long_description="cmemcache -- memcached extension for libmemcache",
      author="Gijsbert de Haan",
      author_email="gijsbert.de.haan@gmail.com",
      url="http://gijsbert.org/cmemcache",
      license="GNU General Public License (GPL)",
      py_modules = ['cmemcache'],
      ext_modules=[cmemcache]
      )
