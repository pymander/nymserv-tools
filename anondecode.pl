#!/usr/bin/perl -w
#
# Decode pseudonym messages.  We read the message in from STDIN, and
# ARGV1 is the passphrase filename.
#
# Copyright (c) 2002, Erik L. Arneson
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or (at
#  your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
#  USA.

use strict;
use Term::ReadKey;
use Crypt::OpenPGP;

my ($msg, $pt, $pgp, @phrases, $dbdir);

# Set this to the spot you're keeping your data files in.
$dbdir = "$ENV{HOME}/.anon/blocks";

$pgp = new Crypt::OpenPGP (Compat  => 'PGP2')
  or die Crypt::OpenPGP->errstr;

# Load our pass phrases for this nick.
my $file = sprintf("%s/%s", $dbdir, $ARGV[0]);
open(IF, "<$file") or die "$file: $!";
@phrases = <IF>;
chomp @phrases;
close(IF);

$msg = join '', <STDIN>;

my $pp;
my $step = 0;
while (@phrases) {
    $pp = shift @phrases;
    $pt = $pgp->decrypt(Data => $msg,
                        Passphrase => $pp)
      or die sprintf("Decryption error: %s\n%s\n", $pgp->errstr,$msg);
    ($msg = $pt) =~ s/\r\n/\n/g;
    $step++;
}

print "[This message was decoded by anondecode.pl ($step steps)]\n";

print $msg;
