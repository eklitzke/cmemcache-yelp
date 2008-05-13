#!/usr/bin/env python
#
# $Id: testReconnect.py 410 2007-08-25 04:42:22Z gijsbert $
#

"""
Do (c)memcache get and set, start, stop memcached by hand to see if get/set reconnects.
"""

import memcache, cmemcache

__version__ = "$Revision: 410 $"
__author__ = "$Author: gijsbert $"

#-------------------------------------------------------------------------------
#
def main():
    import optparse, random
    from time import sleep

    parser = optparse.OptionParser(__doc__.strip())
    parser.add_option( '-n', '--number', action='store', type='int', default=100,
                       help="Number of get/set." )
    parser.add_option( '-v', '--verbose', action='count', default=0,
                       help="Verbose level." )
    opts, args = parser.parse_args()

    servers = ["127.0.0.1:11211", "127.0.0.1:11222"]
    servers = ["127.0.0.1:11211"]

    mc = memcache.Client(servers)
    cmc = cmemcache.Client(servers)

    k = 'bla'
    v = 'bli'
    for i in xrange(opts.number):
        if mc.get(k) == None:
            print 'mc.get() failed'
        else:
            print 'mc.get() succesful'
        if mc.set(k, v) == 0:
            print 'mc.set() failed'
        else:
            print 'mc.set() succesful'

        if cmc.get(k) == None:
            print 'cmc.get() failed'
        else:
            print 'cmc.get() succesful'
        if cmc.set(k, v) == 0:
            print 'cmc.set() failed'
        else:
            print 'cmc.set() success'
            # print 'recreate Client'
            # cmc = cmemcache.Client(servers)

        s = random.random()
        sleep(s)

if __name__ == '__main__':
    main()
