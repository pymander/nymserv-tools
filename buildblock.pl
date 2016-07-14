#!/usr/bin/perl -w
#
# Build a reply block for use with anonymous remailers.
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
use Crypt::OpenPGP;
use Getopt::Std;
use POSIX qw(tmpnam);
use Term::ReadLine;

my ($VERSION, %ARGS, $keyring, $verbose, $dest, %remailers, $rlist,
    @chain, %RL, $term, $pgp, $outfile, $noenckey, $enckeyval, $random,
    @phrases);

$VERSION = '0.02';

getopt('VHEB:krctop', \%ARGS);

# Process our arguments.

if (defined $ARGS{h}
    || !defined($ARGS{c})
    || !defined($ARGS{t})) {
    usage();
}

if (defined $ARGS{k}) {
    $keyring = $ARGS{k};
} else {
    $keyring = "$ENV{HOME}/.pgp/pubring.pgp";
}

if (defined $ARGS{r}) {
    $rlist = $ARGS{r};
} else {
    $rlist = "$ENV{HOME}/.remailers";
}

if (defined $ARGS{v}) {
    $verbose = 1;
} else {
    $verbose = 0;
}

if (defined $ARGS{e}) {
    $noenckey = 1;
} else {
    $noenckey = 0;
}

if (defined $ARGS{p}) {
    $enckeyval = $ARGS{p};
} else {
    undef $enckeyval;
}

if (defined $ARGS{o}) {
    $outfile = $ARGS{o};
} else {
    undef $outfile;
}

if (defined $ARGS{b}) {
    print "Setting up random\n";
    $random = 1;
} else {
    $random = 0;
}

sub usage {
    my $progname = $0;

    # We just want the basename.  Let's make this purdy.
    $progname =~ s@^(?:.*/)?([^/]+)$@$1@;
    
    print qq{Usage: $progname [-v] [-h] [-k keyring] [-r rlist.txt] \\
          [-p passphrase] [-e] [-o outfile.txt] \\
          -c remailer,chain -t dest\@address 

    -h    Print this help message
    -v    Verbose
    -k    Public keyring (defaults to \$HOME/.pgp/pubring.pgp)
    -r    Remailer list (defaults to \$HOME/.remailers)
    -e    Skip Encrypt-Key headers (useful for non-nym blocks)
    -p    Encrypt-Key passphrase
    -o    Output file (defaults to STDOUT)
    -c    Comma-separated remailer chain
    -t    Final destination address
    -b    Build random passphrases

$progname version $VERSION by Erik Arneson <erik\@aarg.net>
This program is distributed under the GNU Public License.
};
    exit 1;
}

sub read_remailers {
    my $rlist = shift @_;
    my ($remailer, $addr, $capstr, @tmp);
    
    if (! -f $rlist ) {
        die "Remailer file list not found: $rlist";
    }

    open(RL, "<$rlist") || die "$rlist: $!";
    while (<RL>) {
        chomp;
        if (m|^\$remailer\{\"([a-z]+)\"\}\s=\s\"<([^>]+)>\s([^\"]+)\"\;$|) {
            $remailer = $1;
            $addr = $2;
            $capstr = $3;

            $RL{$remailer} = { addr => $addr,
                               capstr => [ split(/\s+/, $capstr) ] };
        }
        elsif ($_ eq '-----------------------------------------------------------------------') {
            last;
        }
        else {
            next;
        }
    }
    # Read stats.
    while (<RL>) {
        chomp;
        if (m/^([a-z]+)\s+/) {
            $remailer = $1;
        } else {
            next;
        }
        if (m/\s+([0-9:]+)\s+([0-9\.]+)\%$/) {
            $RL{$remailer}->{latency} = $1;
            $RL{$remailer}->{uptime}  = $2;
        } else {
            die "$_ didn't match";
        }

    }
        
    close(RL);

    if ($verbose == 1) {
        printf("Loaded %d remailers from %s\n",
               scalar(keys %RL),
               $rlist);
    }
}

sub make_block {
    my @chain = @_;
    my ($from, $to, $hop, $head, $body, $file,
        $keyrecip);

    # Init our variables.
    $hop  = scalar(@chain);
    $body = '';

    # We keep reusing the same temp file.  Is that a problem?
    $file = tmpnam();
    
    while (@chain) {
        $to = pop @chain;

        # Do a bit of reporting and set up our $from address correctly.
        if (@chain) {
            $from = $chain[$#chain];
            printf "Hop %d: From: %-8s To: %s\n",
              $hop--, $from, $to;
        } else {
            undef $from;
            printf "Hop %d:   To: %s (First hop)\n", $hop, $to;
        }

        # Handling our final block.
        if (defined $from
            || $noenckey == 0) {
            $head = remail_head($to, $from);
            if ($noenckey == 0) {
                $head .= "\n" . $body . "**\n";
            } else {
                $head .= "\n" . $body;
            }
        } else {
            $head = qq{##
Reply-To: $RL{$to}->{addr}

<your message here>

;;;
Please paste the following "reply block" at the top of your reply to
ensure that it returns to the sender correctly.
$body
};
        }

        print $head if $verbose == 1;
            
        if (defined $from
            && defined $RL{$from}) {
            #printf " --> From (%s) and To (%s)\n",
            #  $from, $to;
            $keyrecip = $RL{$from}->{addr};
            
            open(TMP, ">$file") || die "$file: $!\n";
            print TMP $head;
            close(TMP);

            print "Encrypting $file to $keyrecip ...\n"
              if $verbose == 1;
            printf " --> Encrypting to <%s> now\n", $keyrecip;
            $body = $pgp->encrypt(Filename   => $file,
                                  Recipients => $keyrecip,
                                  Armour     => 1)
              or die $pgp->errstr;
            $body = sprintf("::\nEncrypted: PGP\n\n%s", $body);
        }
    }

    if (defined $outfile) {
        open(OUT, ">$outfile")
          || die "$outfile: $!\n";
        select(OUT);
    }
    print $head;

    if (defined $outfile) {
        close(OUT);
        select(STDOUT);
    }
    
    unlink $file;
}

# This prints out a simple remailer header block.  Multiple nexted
# header blocks make up one reply block.
sub remail_head {
    my $dest   = shift;
    my $from   = shift;
    my ($header, $addr, $enckey, $remix2, $file, @head,
        $prompt);

    $file = tmpnam();
    $remix2 = 0;

    if (defined $from
        && defined $RL{$from}
        && grep { $_ eq 'remix' } @{$RL{$from}->{capstr}}) {
        $remix2 = 1;
    }
    
    if (defined $RL{$dest}) {
        if ($remix2 == 1) {
            # "Remix-To" seems to be broken in reply blocks at the
            # moment.  It works fine with e-mail address, but breaks
            # when using the remailer nickname.  This next line should
            # be swapped in when this bug is fixed.
            #push @head, "Remix-To: $dest";
            push @head, sprintf("Remix-To: %s", $RL{$dest}->{addr});
        } else {
            push @head, sprintf("Anon-To: %s", $RL{$dest}->{addr});
        }
    } else {
        push @head, "Anon-To: $dest";
    }

    if ($noenckey == 0) {
        if ($random == 1) {
            $enckey = rand_phrase();
            print "Random Encrypt-Key: $enckey\n" if $verbose == 1;
        } elsif (defined $enckeyval) {
            $enckey = $enckeyval;
        } else {
            if (defined $RL{$dest}) {
                $prompt = sprintf "Encrypt-Key for %s <%s>: ", $dest, $RL{$dest}->{addr};
            } else {
                $prompt = sprintf "Encrypt-Key for <%s>: ", $dest;
            }
            $enckey = $term->readline($prompt);
            chomp $enckey;
            $term->addhistory($enckey);
        }
        push @head, "Encrypt-Key: $enckey";
        unshift @phrases, $enckey;
    }

    push @head, 'Latent-Time: +0:00';
    
    $header = "::\n" . join("\n", @head) . "\n";

    return $header;
}

# Collect some random data for the seed.
sub rand_seed {
    if ( -r '/dev/random' ) {
        my $rnd;

        open(R, '</dev/random') or
          die "/dev/random: $!\n";
        binmode(R);
        read(R, $rnd, 8);
        close(R);

        return unpack("I", $rnd);
    } else {
        die "No /dev/random!  I cannot generate random numbers.";
    }
}

# Random numbers, '0' through '~' on the ascii chart.
my @RCHARS = ('a' .. 'z', 'A' .. 'Z', '0' .. '9', '/', '-', '_');

sub rand_phrase {
    my @parts;

    for (my $i = 0; $i < 35; $i++) {
        push @parts, $RCHARS[rand(@RCHARS)];
    }

    return join '', @parts;
}

# Main program loop
$dest  = $ARGS{t};
@chain = split(',', $ARGS{c});

if ($noenckey == 0 && $random == 0) {
    $term = new Term::ReadLine 'prompt';
}
$pgp = new Crypt::OpenPGP (Compat  => 'PGP2',
                           PubRing => $keyring);


if (defined $pgp && $verbose == 1) {
    print "Successfully created OpenPGP object...\n";
}

if ($random == 1) {
    # Seed Perl's random number generator using the OS's entropy pool.
    srand(rand_seed());
}

read_remailers($rlist);
make_block(@chain, $dest);

if (@phrases) {
    print join("\n", @phrases), "\n";
}

# End of file.
