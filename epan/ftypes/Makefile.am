# Makefile.am
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include Makefile.common
include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) -I$(top_srcdir)/epan $(WS_CPPFLAGS) \
	$(GLIB_CFLAGS) $(LIBGNUTLS_CFLAGS) $(LIBGCRYPT_CFLAGS)

noinst_LTLIBRARIES = libftypes.la

CLEANFILES = \
	libftypes.a	\
	libftypes.la	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

libftypes_la_SOURCES = $(NONGENERATED_C_FILES) $(NONGENERATED_HEADER_FILES)

EXTRA_DIST = \
	Makefile.common		\
	Makefile.nmake		\
	CMakeLists.txt

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(NONGENERATED_C_FILES)
