# Makefile.PL - CPAN-style build script for causalontology-perl.
#
# Core modules only: ExtUtils::MakeMaker, Digest::SHA, and Math::BigInt all
# ship with Perl itself, so there is nothing to install from CPAN.

use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Causalontology',
    DISTNAME         => 'Causalontology',
    VERSION_FROM     => 'lib/Causalontology.pm',
    ABSTRACT         => 'The Perl binding of the Causalontology standard',
    AUTHOR           => 'AI University (AIU) <ai.university.aiu@gmail.com>',
    LICENSE          => 'apache_2_0',
    MIN_PERL_VERSION => '5.016',
    PREREQ_PM        => {
        # core modules only - listed for explicitness, never fetched
        'Digest::SHA'  => 0,
        'Math::BigInt' => 0,
    },
    META_MERGE => {
        'meta-spec' => { version => 2 },
        resources   => {
            repository => {
                type => 'git',
                url  => 'https://github.com/ai-university-aiu/causalontology.git',
                web  => 'https://github.com/ai-university-aiu/causalontology',
            },
        },
    },
);
