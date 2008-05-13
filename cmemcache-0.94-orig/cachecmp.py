#!/usr/bin/env python
#
# $Id: cachecmp.py 410 2007-08-25 04:42:22Z gijsbert $
#

"""
Test some caching systems of simple string data. Interesting to see what is best to use as a session storage/cache for web apps. Stores: python dict, sql, memcache(d).
"""

import random
import threading
import time
import antiorm

__version__ = "$Revision: 410 $"
__author__ = "$Author: gijsbert $"

#-----------------------------------------------------------------------------------------
#
def createv( n, i, size=1 ):
    """
    Create string value from base 'n' and integer 'i'. Size can be used to make it bigger.
    """
    return (n + '%04d' % i) * size

#-----------------------------------------------------------------------------------------
#
class store(object):
    """
    Store base class.
    """

    def copy( self ):
        """
        Create a copy of the store for multi-thread usage. Default assumes store is
        thread safe and returns self.
        """
        return self

    def teardown( self, nv ):
        """
        Tear down the store, ie remove added keys, etc.
        """

#-----------------------------------------------------------------------------------------
#
class nativestore(store):
    """
    use the python dictionary
    """

    name = 'native'

    def setup( self, nv ):
        self.nv = nv.copy()

    def get( self, name ):
        return self.nv[name]

    def set( self, name, value ):
        self.nv[name] = value

#-----------------------------------------------------------------------------------------
#
class nativestorecopy(store):
    """
    use the python dictionary, but copy the data
    """

    name = 'nativecopy'

    def setup( self, nv ):
        self.nv = nv.copy()

    def get( self, name ):
        return self.nv[name][:]

    def set( self, name, value ):
        self.nv[name] = value[:]

#-----------------------------------------------------------------------------------------
#
class sqlstor(store):
    """
    sql base line.
    """

    name = 'sql'
    table_name = "cachetest"

    def setupDB( self ):
        import psycopg2
        self.dbapi = psycopg2
        self.conn = psycopg2.connect(database='test',
                                     user=opts.user,
                                     password=opts.password)
        the_engine = antiorm.MormConnectionEngine(self.conn)

        class NameValueTable(antiorm.MormTable):
            table = self.table_name
            engine = the_engine
            converters = {
                'name': antiorm.MormConvString(),
                'value': antiorm.MormConvString()
                }
        self.NameValueTable = NameValueTable

    def setup( self, nv ):
        self.setupDB()
        curs = self.conn.cursor()
        try:
            curs.execute( "DROP TABLE %s" % (self.table_name,) )
        except self.dbapi.ProgrammingError:
            # table probably does not exist
            pass
        self.conn.commit()
        curs.execute( """
          CREATE TABLE %s (
            name text primary key,
            value text
          );
          """ % (self.table_name,) )
        
        for n, v in nv.iteritems():
            self.NameValueTable.insert(name=n, value=v)

        self.conn.commit()

    def get( self, name ):
        res = self.NameValueTable.select('WHERE name = %s', (name,), cols=('value',))
        assert(len(res) == 1)
        return res.next().value

    def set( self, name, value ):
        self.NameValueTable.update('WHERE name=%s', (name,), value=value)

#-----------------------------------------------------------------------------------------
#
class memcachedstor(store):
    """
    Use memcached as storage.
    """

    name = 'memcached'

    def __init__( self ):
        import memcache
        servers = ["127.0.0.1:11211"]
        self.mc = memcache.Client(servers, debug=0)
        self.mc.flush_all()

    def setup( self, nv ):
        for n, v in nv.iteritems():
            self.mc.set(n, v)

    def teardown( self, nv ):
        for n in nv.iterkeys():
            self.mc.delete(n)

    def get( self, name ):
        return self.mc.get(name)

    def set( self, name, value ):
        return self.mc.set(name, value)

    def copy( self ):
        """
        memcache object not thread safe, return a new one for each thread.
        """
        # there is no state, so just return a fresh instance
        return memcachedstor()

#-----------------------------------------------------------------------------------------
#
class cmemcachedstor(store):
    """
    Use c-interface to memcached as storage.
    """

    name = 'cmemcached'

    def __init__( self ):
        import cmemcache
        servers = ["127.0.0.1:11211"]
        self.mc = cmemcache.Client(servers, debug=0)
        # fixme: self.mc.flush_all()

    def setup( self, nv ):
        for n, v in nv.iteritems():
            self.mc.set(n, v)

    def get( self, name ):
        return self.mc.get(name)

    def set( self, name, value ):
        return self.mc.set(name, value)

    def copy( self ):
        """
        memcache object not thread safe, return a new one for each thread.
        """
        # there is no state, so just return a fresh instance
        return cmemcachedstor()

#-----------------------------------------------------------------------------------------
#
class poshstor(store):
    """
    Use posh as storage.
    """

    name = 'posh'
    
    def setup( self, nv ):
        import posh
        self.nv = nv.copy()
        self.snv = posh.share(self.nv)

    def get( self, name ):
        return self.snv[name]

#-----------------------------------------------------------------------------------------
#
class test(object):
    """
    Test base class.
    """
    def __init__( self, opts ):
        self.opts = opts

#-----------------------------------------------------------------------------------------
#
class seqtest(test):
    """
    Just get all names.
    """

    name = 'seq'

    def run( self, store, nv ):
        for n,v in nv.iteritems():
            value = store.get(n)
            if value != v:
                print n, value, v, self.name, store.name
                assert(value == v)

#-----------------------------------------------------------------------------------------
#
class seqnotesttest(test):
    """
    Just get all names.
    """

    name = 'seqnotest'

    def run( self, store, nv ):
        get = store.get
        for n in nv.iterkeys():
            get(n)

#-----------------------------------------------------------------------------------------
#
class seqrndwrttest(test):
    """
    Go through all the values and set or get depending on a random function.
    """

    name = 'seqrndwrt'

    def run( self, store, nv ):
        for n,v in nv.iteritems():
            if random.random() < opts.writeratio:
                # just set same value, I don't think that is being optimised in the store
                store.set(n, v)
            else:
                value = store.get(n)
                if value != v:
                    print n, value, v, self.name, store.name
                    assert(value == v)

#-----------------------------------------------------------------------------------------
#
class rndtest(test):
    """
    Just get names in random order.
    """

    name = 'rnd'

    def run( self, store, nv ):
        l = len(nv)
        # make it a sequence, faster
        nvs = zip(nv.iterkeys(), nv.itervalues())
        # for i in xrange(1, l):
        for i in nv.iteritems():
            n, v = random.choice(nvs)
            value = store.get(n)
            assert(value == v)

#-----------------------------------------------------------------------------------------
#
class threadtest(test):
    """
    Run another test in a thread.
    """

    def __init__( self, opts, t ):
        test.__init__(self, opts)
        self.t = t
        self.name = 'thread-' + self.t.name

    def run( self, store, nv ):

        class TestThread(threading.Thread):

            def __init__( self, t, store, nv ):
                threading.Thread.__init__(self)
                self.t = t
                self.store = store
                self.nv = nv

            def run( self ):
                self.t.run( self.store, self.nv )
        
        threads = []
        for i in xrange(self.opts.threads):
            t = TestThread(self.t, store.copy(), nv)
            threads.append(t)
        
        for t in threads:
            t.start()

        for t in threads:
            t.join()

#-------------------------------------------------------------------------------
#
def main():
    import optparse
    parser = optparse.OptionParser(__doc__.strip())
    # on laptops with cpu speed control numpairs should be high enough that creating the
    # name,value pairs brings the cpu to full speed.
    parser.add_option('-n', '--numpairs', action='store', type='int',
                      default=10000,
                      help="Number of name,value pairs to test with." )
    parser.add_option('-k', '--namemult', action='store', type='int',
                      default=4,
                      help="Name/key size multiplier." )
    parser.add_option('-v', '--valuemult', action='store', type='int',
                      default=400,
                      help="Value size multiplier." )
    # NOTE: when the seq test fails on the value == v check, that means that there was too
    # little space in memcached to store all name,value pairs. Restart, and if it still
    # fails restart with more memory.

    parser.add_option('-t', '--threads', action='store', type='int',
                      default=10,
                      help="Number of threads to run." )
    parser.add_option('-w', '--writeratio', action='store', type='float',
                      default=0.25,
                      help="Ratio of write:read actions." )

    parser.add_option('-u', '--user', action='store',
                      default='gijsbert',
                      help="DB user")
    parser.add_option('-p', '--password', action='store',
                      default='hAAn',
                      help="DB password")

    global opts
    opts, args = parser.parse_args()
    assert(opts.numpairs > 0)

    print 'Setting up %d name,value pairs' % opts.numpairs
    nv = {}
    nsz, vsz = 0, 0
    for i in range(1, opts.numpairs):
        # name = createn('name', i)
        name = createv('name', i, opts.namemult)
        nsz += len(name)
        value = createv('value', i, opts.valuemult)
        vsz += len(value)
        nv[name] = value

    # stors = [ nativestore(), sqlstor(), memcachedstor(), poshstor() ]
    stors = [ nativestore(),
              nativestorecopy(),
              # sqlstor(),
              memcachedstor(),
              cmemcachedstor() ]
    for s in stors:
        print 'Initializing', s.name
        s.setup(nv)

    tests = [ seqtest(opts),
              seqnotesttest(opts),
              seqrndwrttest(opts),
              rndtest(opts)
              #,
              # threaded test does not tell us anything new:
              # threadtest(opts, seqtest(opts))
              ]
    stats = {}
    for t in tests:
        lstats = {}
        for s in stors:
            print 'Doing %d iterations of %s with %s' % (opts.numpairs, t.name, s.name)
            
            # reset random so they all do the same thing
            random.seed(12)
            t0 = time.time()
            t.run(s, nv)
            t1 = time.time()
            lstats[s] = t1-t0
            print 'time elapsed ', t1-t0
            print 'per get      ', (t1-t0)/opts.numpairs
        stats[t] = lstats

    for s in stors:
        print 'Finalizing', s.name
        s.teardown(nv)

    print
    print 'Name/Value size %d/%d total %d bytes' % \
        ((vsz/opts.numpairs), (nsz/opts.numpairs), vsz)
    print
    print '%14s %s' % ('', ' '.join('%14s' %s.name for s in stors))
    for t in tests:
        print '%14s' % (t.name,),
        for s in stors:
            print '%14.8f' % (stats[t][s],),
        print

    print
    print '%14s %s' % ('', ' '.join('%14s' %s.name for s in stors))
    for t in tests:
        print '%14s' % (t.name,),
        for s in stors:
            print '%14.8f' % (stats[t][s]/stats[tests[0]][stors[0]],),
        print

if __name__ == '__main__':
    main()
