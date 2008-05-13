EXTRA_DIST = ChangeLog
INCLUDES = -I${top_srcdir}/include
SUBDIRS = doc include src test

ChangeLog: .PHONY
	$(BIN_SVN2CL)

# A target for easily killing/restarting memcached(8)
reset: .PHONY
	-$(BIN_KILLALL) memcached
	/usr/bin/nice -20 $(BIN_MEMCACHED) -d -p 11211
	/usr/bin/nice -20 $(BIN_MEMCACHED) -d -p 11212
	/usr/bin/nice -20 $(BIN_MEMCACHED) -d -p 11213
	/usr/bin/nice -20 $(BIN_MEMCACHED) -d -p 11214

# The 'test' target runs regression tests
test: check
	cd test; $(MAKE) run

dist-hook:
	rm -f $(distdir)/regen
