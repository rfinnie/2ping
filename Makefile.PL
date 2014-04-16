use strict;
BEGIN {
        require 5.006;
}

use ExtUtils::MakeMaker;

WriteMakefile(
  META_MERGE => {
    resources => {
      repository => 'https://github.com/rfinnie/2ping',
    },
  },
  NAME => '2ping',
  ABSTRACT_FROM => 'script/2ping.in',
  VERSION_FROM => 'script/2ping.in',
  AUTHOR => 'Ryan Finnie <ryan@finnie.org>',
  LICENSE => 'gpl',
  MIN_PERL_VERSION => 5.006,
  PREREQ_PM => {
    'Getopt::Long' => 0,
    'Pod::Usage' => 0,
    'IO::Select' => 0,
    'IO::Socket::INET' => 0,
    'Time::HiRes' => 0,
  },
  EXE_FILES => [
    'script/2ping'
  ],
  PL_FILES => {
    'script/build.PL' => 'script/2ping'
  },
  MAN1PODS => {
    'script/2ping'  => 'blib/man1/2ping.1p',
  },
  clean => {
    FILES => 'script/2ping',
  },
);
