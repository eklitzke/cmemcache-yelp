#
# $Id: Makefile 391 2006-12-01 22:18:19Z gijsbert $
#

# all builds index.html
.PHONY: all
all: index.html

# Firgure out restructured test to to html command
# (http://docutils.sourceforge.net/rst.html) Use our special projects-rst2html to get our
# style, otherwise fall back to default
RST2HTML ?= $(wildcard $(PROJECTS)/projects/bin/projects-rst2html)
ifeq ($(strip $(RST2HTML)),)
RST2HTML = rst2html.py --no-raw -r 3
else
RST2HTML += --project-header
endif

# Build index.html from README file.
index.html: README Makefile
	$(RST2HTML) $< $@

# test
.PHONY: runtests
runtests: all
	python test.py

# Cleanup.
.PHONY: clean
clean:
	-rm -f *.pyc
	-rm -rf build
