#!/usr/bin/perl
#
# Decode pseudonym messages.  We read the message in from STDIN, and
# ARGV1 is the passphrase filename.

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
      or die sprintf("Decryption error: %s\n%s\n",$pgp->errstr,$msg);
    ($msg = $pt) =~ s/\r\n/\n/g;
    $step++;
}

print "[This message was decoded by anondecode.pl ($step steps)]\n";

print $msg;
