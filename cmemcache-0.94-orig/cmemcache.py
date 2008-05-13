#!/usr/bin/env python
#
# $Id: cmemcache.py 431 2008-05-03 03:23:03Z gijsbert $
#

""" The StringClient extension only supports string values. This module derives a
Client from StringClient to support any picklable object. Logic is a straight copy
from memcache.py.

Overview
========

See U{the MemCached homepage<http://www.danga.com/memcached>} for more about memcached.

Usage summary
=============

This should give you a feel for how this module operates:

    import memcache
    mc = memcache.Client(['127.0.0.1:11211'], debug=0)

    mc.set("some_key", "Some value")
    value = mc.get("some_key")

    mc.set("another_key", 3)
    mc.delete("another_key")
    
    mc.set("key", "1")   # note that the key used for incr/decr must be a string.
    mc.incr("key")
    mc.decr("key")

The standard way to use memcache with a database is like this:

    key = derive_key(obj)
    obj = mc.get(key)
    if not obj:
        obj = backend_api.get(...)
        mc.set(obj)

    # we now have obj, and future passes through this code
    # will use the object from the cache.

Detailed Documentation
======================

More detailed documentation is available in the L{Client} and L{StringClient} class.
"""

__version__ = "$Revision: 431 $"
__author__ = "$Author: gijsbert $"

import traceback
import types
try:
    import cPickle as pickle
except ImportError:
    import pickle

from _cmemcache import StringClient

#-----------------------------------------------------------------------------------------
#
def stderrlog(str):
    """
    Log to stderr.
    """
    import sys
    sys.stderr.write("MemCached: %s\n" % str)

# Override with your own function to integrate with some other logging mechanism
# To get any output one must create a Client(..., debug=1)
log = stderrlog

#-----------------------------------------------------------------------------------------
#
class Client(StringClient):
    """
    Use memcached flags parameter to set/add/replace to handle any python class as
    the cache value. Also does int, long conversion to/from string.
    """

    _FLAG_PICKLE  = 1<<0
    _FLAG_INTEGER = 1<<1
    _FLAG_LONG    = 1<<2

    def __init__(self, servers, debug=0):
        """
        Create a new Client object with the given list of servers.

        @param servers: C{servers} is passed to L{set_servers}.
        @param debug: whether to display error messages when a server can't be
        contacted. (A lot less verbose than memcache.py).
        """
        StringClient.__init__(self, servers)
        self.debug = debug
    
    def _convert(self, val):
        """
        Convert val to str, flags tuple.
        """
        if isinstance(val, types.StringTypes):
            flags = 0
        elif isinstance(val, int):
            flags = Client._FLAG_INTEGER
            val = "%d" % val
        elif isinstance(val, long):
            flags = Client._FLAG_LONG
            val = "%d" % val
        else:
            flags = Client._FLAG_PICKLE
            val = pickle.dumps(val, 2)
        return (val, flags)

    def set(self, key, val, time=0):
        """
        Unconditionally sets a key to a given value in the memcache.

        The C{key} can optionally be an tuple, with the first element being the
        hash value, if you want to avoid making this module calculate a hash value.
        You may prefer, for example, to keep all of a given user's objects on the
        same memcache server, so you could use the user's unique id as the hash
        value.

        @return: Nonzero on success.
        @rtype: int
        """
        val, flags = self._convert(val)
        return StringClient.set(self, key, val, time, flags)

    def add(self, key, val, time=0):
        """
        Add new key with value.
        
        Like L{set}, but only stores in memcache if the key doesn't already exist.

        @return: Nonzero on success.
        @rtype: int
        """
        val, flags = self._convert(val)
        return StringClient.add(self, key, val, time, flags)

    def replace(self, key, val, time=0):
        """
        Replace existing key with value.
        
        Like L{set}, but only stores in memcache if the key already exists.  
        The opposite of L{add}.

        @return: Nonzero on success.
        @rtype: int
        """
        val, flags = self._convert(val)
        return StringClient.replace(self, key, val, time, flags)

    def get(self, key):
        """
        Retrieves a key from the memcache.
        
        @return: The value or None if key doesn't exist (or if there are decoding errors).
        """
        val = StringClient.getflags(self, key)
        if val:
            buf, flags = val
            if flags == 0:
                val = buf
            elif flags & Client._FLAG_INTEGER:
                val = int(buf)
            elif flags & Client._FLAG_LONG:
                val = long(buf)
            elif flags & Client._FLAG_PICKLE:
                try:
                    val = pickle.loads(buf)
                except:
                    self.debuglog('Pickle error...\n%s' % traceback.format_exc())
                    val = None
            else:
                self.debuglog("unknown flags on get: %x\n" % flags)
                val = None

        return val
        
    def get_multi(self, keys):
        return StringClient.get_multiflags(self, keys)

    def debuglog(self, str):
        if self.debug:
            log(str)

