use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Trustforge',
    VERSION_FROM     => 'lib/Trustforge.pm',
    AUTHOR           => 'TrustForge contributors <dev@trustforge.local>',
    LICENSE          => 'apache_2_0',
    MIN_PERL_VERSION => '5.020',
    PREREQ_PM        => {
        'JSON::PP'        => 0,
        'LWP::UserAgent'  => 0,
        'HTTP::Request'   => 0,
        'URI'             => 0,
    },
    TEST_REQUIRES    => {
        'Test::More'      => 0,
        'Test::Exception' => 0,
    },
    test             => { TESTS => 't/*.t' },
);
