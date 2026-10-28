# required Python modules 
if COND_REGRESS
  MAYBE_REGRESS = regress
endif
SUBDIRS = . $(MAYBE_REGRESS)

AUTOMAKE_OPTIONS = foreign no-dependencies

########################################################################
##
## libhoneyd, the honeyd preload library. Wrapped around
## server applications to make them communicate through
## honeyd.
##
########################################################################

## Preload library
## This is how it should work but libtool is so broken
#pkglib_LTLIBRARIES = libhoneyd.la 
#libhoneyd_la_SOURCES = honeyd_overload.c atomicio.c fdpass.c fdpass.h
#libhoneyd_la_LDFLAGS = -module -export-dynamic -avoid-version

## Bad hack with help from marius@monkey.org to actually get this 
## working on Linux
## The preload objects get their own names: atomicio.c and fdpass.c are
## also compiled into honeyd, and a libtool compile of foo.lo writes foo.o
## too, so sharing names lets parallel make clobber honeyd's objects
## mid-link (#18).
LIBHONEYDFILES= libhoneyd-honeyd_overload.lo libhoneyd-atomicio.lo \
		libhoneyd-fdpass.lo

libhoneyd-honeyd_overload.lo: honeyd_overload.c config.h
	$(LTCOMPILE) -c -o $@ $(srcdir)/honeyd_overload.c
libhoneyd-atomicio.lo: atomicio.c atomicio.h config.h
	$(LTCOMPILE) -c -o $@ $(srcdir)/atomicio.c
libhoneyd-fdpass.lo: fdpass.c fdpass.h config.h
	$(LTCOMPILE) -c -o $@ $(srcdir)/fdpass.c

libphantom-mirage.so: $(LIBHONEYDFILES)
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) -o libtmp$@.la \
		-rpath $(libdir)/phantom-mirage $(LIBHONEYDFILES) $(LIBS) $(LDFLAGS) \
		-module -avoid-version -nostdlib @LIBDL@
	rm -f libtmp$@.la tmp$@.so* $@
	cp .libs/libtmp$@.so $@ || cp .libs/libtmp$@ $@
	rm -f .libs/libtmp$@.*

libhoneyddir = $(libdir)/phantom-mirage
libhoneyd_DATA = libphantom-mirage.so


# Configuration files for Honeyd
honeyddatadir = $(datadir)/phantom-mirage
honeydlibdir = $(libdir)/phantom-mirage
honeydincludedir = $(includedir)/honeyd
honeyddata_DATA = README.md nmap.assoc xprobe2.conf nmap-os-db config.sample \
		config.ethernet pf.os nmap-mac-prefixes \
		fingerprints/columbo-v1.db fingerprints/columbo-v1.db.sha256

honeydplugins = @PLUGINS@
honeydpluginsdeclare = @PLUGINSDECLARE@

########################################################################
##
## Honeyd itself. It uses plugins, so we need to install a few header
## files that plugins can pick up when being built so that they know
## how to register etc.
##
########################################################################

bin_PROGRAMS = phantom-mirage phantom-mirage-ctl phantom-mirage-stats phantom-mirage-sniff
honeyddata_PROGRAMS = $(SMTP_BIN) $(PROXY_BIN)
EXTRA_PROGRAMS = smtp proxy

# Install the header files in a separate subdirectory. Note that
# honeydincludedir is the directory reported to the user, who has to
# use that directory as an -I include directive with #include <honeyd/foo.h>.
# pkgincludedir includes the additional honeyd directory since that's
# where the headers are actually installed.
pkgincludedir = $(honeydincludedir)
pkginclude_HEADERS = hooks.h plugins.h plugins_config.h debug.h

phantom_mirage_SOURCES	= honeyd.c command.c parse.y lex.l config.c personality.c sandbox.c sandbox.h \
	sandbox_daemon.c sandbox_daemon_list.h sandbox_ns_list.h sandbox_ns.c sandbox_root.c \
	util.c ipfrag.c router.c tcp.c udp.c xprobe_assoc.c log.c \
	fdpass.c atomicio.c atomicio.h subsystem.c hooks.c plugins.c \
	plugins_config.c pool.c interface.c arp.c gre.c \
	honeyd.h personality.h ipfrag.h	router.h network.c network.h \
	tcp.h udp.h parse.h \
	xprobe_assoc.h subsystem.h fdpass.h hooks.h plugins.h \
	plugins_config.h template.h pool.h interface.h arp.h gre.h \
	log.h pfctl_osfp.c pf_osfp.c pfvar.h condition.c condition.h \
	osfp.c osfp.h ui.c ui.h ethernet.c ethernet.h \
	parser.h tagging.c tagging.h stats.c stats.h \
	dhcpclient.c dhcpclient.h rrdtool.c rrdtool.h \
	histogram.c histogram.h untagging.c untagging.h

phantom_mirage_DEPENDENCIES = @PYEXTEND@ @LIBOBJS@
phantom_mirage_LDADD = @PYEXTEND@ @LIBOBJS@ @PYTHONLIB@ @EVENTLIB@ @PCAPLIB@ \
	@DNETLIB@ @ZLIB@ @PLUGINLIB@ -lm

# Allow plugins to use honeyd's functions:
phantom_mirage_LDFLAGS = -export-dynamic 

# Honeyd stats collector
#
phantom_mirage_stats_SOURCES = honeydstats.c honeydstats.h \
	honeydstats_main.c tagging.c tagging.h \
	stats.c stats.h util.c histogram.c histogram.h analyze.c analyze.h \
	untagging.c untagging.h filter.c filter.h keycount.c keycount.h
phantom_mirage_stats_LDADD = @LIBOBJS@ @DNETLIB@ @EVENTLIB@ @ZLIB@
phantom_mirage_stats_CPPFLAGS = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @ZINC@
phantom_mirage_stats_CFLAGS = -O0 -Wall

#
# Honeyd stats sniffer
#

phantom_mirage_sniff_SOURCES = hsniff.c hsniff.h tagging.c tagging.h \
	stats.c stats.h util.c util.h hooks.c hooks.h interface.c interface.h \
	pfctl_osfp.c pf_osfp.c pfvar.h osfp.c osfp.h network.c network.h
phantom_mirage_sniff_LDADD = @LIBOBJS@ @PCAPLIB@ @DNETLIB@ @EVENTLIB@ @ZLIB@
phantom_mirage_sniff_CPPFLAGS = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@EVENTINC@ @PCAPINC@ @DNETINC@ @ZINC@
phantom_mirage_sniff_CFLAGS = -O2 -Wall -DPATH_HONEYDDATA="\"$(honeyddatadir)\""

#
# Honeyd control application
#
phantom_mirage_ctl_SOURCES = honeydctl.c
phantom_mirage_ctl_LDADD = @LIBOBJS@ @EDITLIB@ @LIBCURSES@
phantom_mirage_ctl_CPPFLAGS = @EDITINC@
phantom_mirage_ctl_CFLAGS = -O2 -Wall

CFLAGS	= -O2 -Wall -g \
	-DPATH_HONEYDINCLUDE="\"$(honeydincludedir)\"" \
	-DPATH_HONEYDDATA="\"$(honeyddatadir)\"" \
	-DPATH_HONEYDLIB="\"$(honeydlibdir)\"" \
	-DHONEYD_PLUGINS_DECLARE="$(honeydpluginsdeclare)" \
	-DHONEYD_PLUGINS="$(honeydplugins)" \
	-DPATH_RRDTOOL="\"$(PATH_RRDTOOL)\"" \
	-D_GNU_SOURCE

INCLUDES = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@PYTHONINC@ @EVENTINC@ @PCAPINC@ @DNETINC@ @ZINC@

########################################################################
## Simple subsystems to be used with Honeyd
########################################################################

smtp_SOURCES = subsystems/smtp.c subsystems/smtp.h subsystems/smtp_main.c \
	subsystems/smtp_messages.h atomicio.c atomicio.h \
	util.c util.h honeyd_overload.h

smtp_LDADD = @LIBOBJS@ @EVENTLIB@ @DNETLIB@ @PCAPLIB@ @PCRELIB@
smtp_CPPFLAGS = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @PCREINC@
smtp_CFLAGS = -O2 -Wall

proxy_SOURCES = subsystems/proxy.c subsystems/proxy.h subsystems/proxy_main.c \
	subsystems/proxy_messages.h subsystems/smtp.c subsystems/smtp.h \
	subsystems/smtp_messages.h atomicio.c atomicio.h \
	util.c util.h honeyd_overload.h

proxy_LDADD = @LIBOBJS@ @EVENTLIB@ @DNETLIB@ @PCAPLIB@ @PCRELIB@
proxy_CPPFLAGS = -I$(top_srcdir)/@DNETCOMPAT@ -I$(top_srcdir)/compat \
	@EVENTINC@ @DNETINC@ @PCREINC@
proxy_CFLAGS = -O2 -Wall

########################################################################
##
## Miscellaneous stuff -- files we need to include in the package,
## manpage, yacc/lex stuff etc.
##
########################################################################

man_MANS = phantom-mirage.8 phantom-mirage-ctl.1 phantom-mirage-stats.1 phantom-mirage-sniff.1

WEBDIR_FILES = \
	webserver/htdocs/images/logo.gif webserver/htdocs/images/edit.gif \
	webserver/htdocs/images/delete.gif webserver/htdocs/images/add.gif \
	webserver/htdocs/images/arrow_down.gif \
	webserver/htdocs/images/arrow_right.gif \
	webserver/htdocs/images/google_logo.gif \
	webserver/htdocs/images/phantom-mirage-logo.png \
	webserver/htdocs/images/favicon.svg \
	webserver/htdocs/images/favicon-32.png \
	webserver/htdocs/graphs/traffic_daily.gif \
	webserver/htdocs/graphs/traffic_hourly.gif \
	webserver/htdocs/styles/layout.css \
	webserver/server.py

# Automake sucks - but that's ok

# TODO: Fix this, half the scripts are missing and this will probably break gzipping
EXTRA_DIST = $(man_MANS) $(WEBDIR_FILES)		  \
	acconfig.h $(honeyddata_DATA) LICENSE NOTICE sha1.c			  \
	compat/sys/tree.h compat/sys/queue.h compat/err.h compat/sha1.h	  \
	compat/libdnet/dnet.h compat/getopt.h				  \
	honeyd_overload.c pyextend.c pyextend.h \
	pydataprocessing.c pydataprocessing.h \
	pydatahoneyd.c pydatahoneyd.h scripts

# The --sandbox-scripts launcher is the same binary under its own name, so
# that an AppArmor profile can grant "userns" to it alone (#16).
install-exec-hook:
	$(mkdir_p) "$(DESTDIR)$(honeydlibdir)"
	cp -f "$(DESTDIR)$(bindir)/phantom-mirage$(EXEEXT)" \
	    "$(DESTDIR)$(honeydlibdir)/pm-script-ns$(EXEEXT)"

install-data-local:
	$(mkdir_p) "$(DESTDIR)$(honeyddatadir)"
	(cd $(top_srcdir) && tar -cf - $(top_srcdir)/webserver) | \
	(cd $(DESTDIR)$(honeyddatadir) && tar -xf -)
	find $(DESTDIR)$(honeyddatadir)/webserver -type f | xargs chmod a+r
	find $(DESTDIR)$(honeyddatadir)/webserver -type d | xargs chmod a+xr
	(cd $(top_srcdir) && tar -cf - $(top_srcdir)/scripts) | \
	(cd $(DESTDIR)$(honeyddatadir) && tar -xf -)
# No Python at install time (#36). scripts/lib/init.py used to create the
# names database in the *installing* user's home; the service scripts
# (nbns.py, mdns.py) create it on first use via names.InitializeDB(), and
# init.py remains as an optional Python 3 helper.

# parse.c/parse.h/lex.c are generated by bison/flex (no longer tracked, #66);
# lex.c includes parse.h, so make sure the header exists before any compile.
BUILT_SOURCES = parse.h

CLEANFILES = *.so
DISTCLEANFILES = *~

LEX_OUTPUT_ROOT = lex.hyd
LFLAGS  = -Phyd
YFLAGS  = -d
