# Makefile.PL - CPAN-style build script for causalontology-perl.
#
# Core modules only: ExtUtils::MakeMaker, Digest::SHA, and Math::BigInt all
# ship with Perl itself, so there is nothing to install from CPAN.

use strict;
use warnings;
use ExtUtils::MakeMaker;
use File::Find ();

# The twenty-one JSON Schemas are data the binding cannot validate without,
# so they are shipped inside the distribution rather than read out of a
# repository checkout. File::ShareDir::Install would be the usual vehicle,
# but it is not a core module and this distribution deliberately has no CPAN
# dependencies at all; instead the schemas ride along in the PM map and land
# beside the modules at <libdir>/Causalontology/share/schema, which is where
# Causalontology::Schema::_schema_dir() looks for them.
my %PM;
File::Find::find({
    no_chdir => 1,
    wanted   => sub {
        return unless -f $_;
        return unless /\.pm\z/;
        (my $dest = $_) =~ s{\Alib/}{};
        $PM{$_} = '$(INST_LIB)/' . $dest;
    },
}, 'lib');

for my $schema (sort glob 'share/schema/*.schema.json') {
    my ($file) = $schema =~ m{([^/]+)\z};
    $PM{$schema} = '$(INST_LIB)/Causalontology/share/schema/' . $file;
}

die "Makefile.PL: no vendored schemas found under share/schema - "
  . "copy spec/schema/*.schema.json there before building\n"
    unless grep { m{\Ashare/schema/} } keys %PM;

WriteMakefile(
    PM               => \%PM,
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
