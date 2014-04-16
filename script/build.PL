#!/usr/bin/perl

use strict;
use warnings;

if((scalar @ARGV) == 0) {
  die "Usage: $0 files [files...]\n";
}

my %r = ();
my @replacements = qw/EXTRAVERSION/;
foreach my $replacement (@replacements) {
  $r{$replacement} = ($ENV{'EXTRAVERSION'} ? $ENV{'EXTRAVERSION'} : '');
}

foreach my $file (@ARGV) {
  my $filein = "$file.in";
  open(FILEIN, '<', $filein) || die "Cannot open $filein: $!";
  open(FILEOUT, '>', $file) || die "Cannot open $file: $!";
  while(my $l = <FILEIN>) {
    foreach my $replacement (keys %r) {
      $l =~ s/#${replacement}#/$r{$replacement}/g;
    }
    print FILEOUT $l;
  }
  close(FILEOUT);
  close(FILEIN);
}
