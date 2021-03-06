#!/usr/bin/perl

my $debug = 0;
# 0: off
# 1: specific debug
# 2: full debug

#
# Generate the AUTHORS file combining existing AUTHORS file with
# git commit log.
#
# Usage: generate_authors.pl <original AUTHORS file> <output of git shortlog>

#
# Copyright 2016 Michael Mann (see AUTHORS file)
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

use warnings;
use strict;
use Getopt::Long;

my $state = "";
my %contributors = ();
my $is_contributing = 0;
my $crlf_find = "\n";
my $crlf_replace = "\r\n";

my $header = "

Original Author
-------- ------
Gerald Combs            <gerald[AT]wireshark.org>


";

my $trailer = "

Acknowledgements
------------
Dan Lasley <dlasley[AT]promus.com> gave permission for his
dumpit() hex-dump routine to be used.

Mattia Cazzola <mattiac[AT]alinet.it> provided a patch to the
hex dump display routine.

We use the exception module from Kazlib, a C library written by
Kaz Kylheku <kaz[AT]ashi.footprints.net>. Thanks go to him for
his well-written library. The Kazlib home page can be found at
http://users.footprints.net/~kaz/kazlib.html

We use Lua BitOp, written by Mike Pall, for bitwise operations
on numbers in Lua. The Lua BitOp home page can be found at
http://bitop.luajit.org/

Henrik Brix Andersen <brix[AT]gimp.org> gave permission for his
webbrowser calling routine to be used.

Christophe Devine <c.devine[AT]cr0.net> gave permission for his
SHA1 routines to be used.

snax <snax[AT]shmoo.com> gave permission to use his(?) weak key
detection code from Airsnort.

IANA gave permission for their port-numbers file to be used.

We use the natural order string comparison algorithm, written by
Martin Pool <mbp[AT]sourcefrog.net>.

Emanuel Eichhammer <support[AT]qcustomplot.com> granted permission
to use QCustomPlot.
";

my $git_log_text = "
From git log
---------------
";

# Perl trim function to remove whitespace from the start and end of the string
sub trim($)
{
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

sub parse_author_name {
	my $full_name = $_[0];

	if ($full_name =~ /^([\w\.\-\'\x80-\xff]+(\s*[\w+\.\-\'\x80-\xff])*)\s+<([^>]*)>/) {
		#Make an exception for Gerald because he's part of the header
		if ($3 ne "gerald[AT]wireshark.org") {
			$contributors{$3} = $1;
			print "$full_name\n";
		}
	} elsif ($full_name =~ /^([\w\.\-\'\x80-\xff]+(\s*[\w+\.\-\'\x80-\xff])*)\s+\(/) {
		$contributors{"<no_email>"} = $1;
		print "$full_name\n";
	}
}

sub parse_git_name {
	my $full_name = $_[0];
	my $name;
	my $find = "\@";
	my $replace = "[AT]";
	my $email;

	if ($full_name =~ /^([^<]*)\s*<([^>]*)>/) {
		$name = $1;
		#Convert real email address to "spam proof" one
		$email = $2;
		$email =~ s/$find/$replace/g;

		if (!exists($contributors{ $email })) {
			#Make an exception for Gerald because he's part of the header
			if ($email ne "gerald[AT]wireshark.org") {
				print "$name\t\t$email\r\n";
			}
		}
	}
}

# ---------------------------------------------------------------------
#
# MAIN
#

$header =~ s/$crlf_find/$crlf_replace/g;
print $header;

open( my $author_fh, '<', $ARGV[0] ) or die "Can't open $ARGV[0]: $!";
while ( my $line = <$author_fh> ) {
	chomp $line;

	last if ($line =~ "Acknowledgements");

	if ($line =~ "Contributors") {
		$is_contributing = 1;
	} elsif ($is_contributing == 0) {
		next;
	}

	if ($line =~ /([^\{]*)\{/) {
		parse_author_name($line);
		$state = "s_in_bracket";
	} elsif ($state eq "s_in_bracket") {
		if ($line =~ /([^\}]*)\}/) {
			print "$line\n";
			$state = "";
		} else {
			print "$line\n";
		}
	} elsif ($line =~ /</) {
		parse_author_name($line);
	} elsif ($line =~ "(e-mail address removed at contributor's request)") {
		parse_author_name($line);
	} else {
		print "$line\n";
	}
}
close $author_fh;

$git_log_text =~ s/$crlf_find/$crlf_replace/g;
print $git_log_text;

open( my $git_author_fh, '<', $ARGV[1] ) or die "Can't open $ARGV[1]: $!";

while ( my $git_line = <$git_author_fh> ) {
	chomp $git_line;

	parse_git_name($git_line);
}
close $git_author_fh;

$trailer =~ s/$crlf_find/$crlf_replace/g;
print $trailer;

__END__
