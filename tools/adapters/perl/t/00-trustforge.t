#!perl
use strict;
use warnings;
use 5.020;

use Test::More;
use Test::Exception;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Trustforge;
use HTTP::Response;

# ---------------------------------------------------------------------------
# Tiny mock UA. We use this in lieu of Test::LWP::UserAgent so the
# test has zero CPAN dependencies beyond Test::More + Test::Exception.
# ---------------------------------------------------------------------------
{
    package MockUA;
    sub new {
        my ($class, %args) = @_;
        bless {
            queue   => $args{queue} || [],
            history => [],
        }, $class;
    }
    sub request {
        my ($self, $req) = @_;
        push @{ $self->{history} }, $req;
        my $resp = shift @{ $self->{queue} };
        return $resp || HTTP::Response->new(500, 'No mock response');
    }
    sub timeout { }
}

sub mock_response {
    my ($status, $body) = @_;
    my $r = HTTP::Response->new($status, 'OK');
    $r->header('Content-Type' => 'application/json');
    $r->content($body);
    return $r;
}

# ---------------------------------------------------------------------------
# encode_request_body
# ---------------------------------------------------------------------------
subtest 'encode_request_body: minimal' => sub {
    my $body = Trustforge->encode_request_body({ action => 'fs.read' });
    like   $body, qr/"action":"fs\.read"/, 'has action';
    unlike $body, qr/host_token/,           'no host_token';
    unlike $body, qr/target/,               'no target';
};

subtest 'encode_request_body: full' => sub {
    my $body = Trustforge->encode_request_body({
        action          => 'net.connect',
        host_token      => 'abc',
        host_token_kind => 'session',
        target          => '/x',
        trace_id        => 'tf-1',
    });
    like $body, qr/"host_token":"abc"/,           'host_token';
    like $body, qr/"host_token_kind":"session"/,  'host_token_kind';
    like $body, qr/"target":"\/x"/,               'target';
    like $body, qr/"trace_id":"tf-1"/,            'trace_id';
};

subtest 'encode_request_body: requires action' => sub {
    dies_ok { Trustforge->encode_request_body({}) } 'no action -> dies';
};

# ---------------------------------------------------------------------------
# parse_response_body
# ---------------------------------------------------------------------------
subtest 'parse_response_body: allow' => sub {
    my $r = Trustforge->parse_response_body(
        '{"decision":"allow","reason":"ok","proof_id":"p1","danger_tags":["fs.read"]}'
    );
    is        $r->{decision}, 'allow', 'decision';
    is        $r->{proof_id}, 'p1',    'proof_id';
    is_deeply $r->{danger_tags}, ['fs.read'], 'tags';
};

subtest 'parse_response_body: approval-required' => sub {
    my $r = Trustforge->parse_response_body(
        '{"decision":"approval-required","reason":"need","proof_id":"p2","approval_id":"a-9","danger_tags":[]}'
    );
    is $r->{decision},    'approval-required', 'decision';
    is $r->{approval_id}, 'a-9',                'approval_id';
};

subtest 'parse_response_body: rejects malformed JSON' => sub {
    eval { Trustforge->parse_response_body('not json') };
    my $err = $@;
    ok $err, 'died';
    is ref($err) eq 'HASH' ? $err->{kind} : '', 'invalid-response',
        'invalid-response kind';
};

# ---------------------------------------------------------------------------
# extract_bearer
# ---------------------------------------------------------------------------
subtest 'extract_bearer' => sub {
    is(Trustforge->extract_bearer('Bearer abc'),    'abc',  'mixed case');
    is(Trustforge->extract_bearer('bearer xyz'),    'xyz',  'lowercase');
    is(Trustforge->extract_bearer('Bearer  tok  '), 'tok',  'trims');
    is(Trustforge->extract_bearer('Bearer '),       undef,  'empty');
    is(Trustforge->extract_bearer('Basic abc'),     undef,  'wrong scheme');
    is(Trustforge->extract_bearer(undef),           undef,  'undef in');
};

# ---------------------------------------------------------------------------
# decision_response
# ---------------------------------------------------------------------------
subtest 'decision_response' => sub {
    my @r;

    @r = Trustforge->decision_response({ decision => 'allow' });
    is scalar(@r), 1, 'allow returns single undef';
    is $r[0], undef, 'allow undef';

    my ($s, $h, $b) =
        Trustforge->decision_response({ decision => 'deny', reason => 'no' });
    is $s, 403, 'deny status';
    like $b, qr/"deny"/, 'deny body';

    ($s, $h, $b) = Trustforge->decision_response({
        decision    => 'approval-required',
        approval_id => 'a-7',
    });
    is $s, 202, 'approval status';
    is_deeply $h, ['Content-Type' => 'application/json',
                   'X-TF-Approval-Id' => 'a-7'], 'approval headers';

    ($s, $h, $b) = Trustforge->decision_response({ decision => 'wat' });
    is $s, 503, 'unknown status';
};

# ---------------------------------------------------------------------------
# decide() with mocked UA
# ---------------------------------------------------------------------------
subtest 'decide: allow path' => sub {
    my $ua = MockUA->new(queue => [
        mock_response(200,
            '{"decision":"allow","reason":"","proof_id":"p"}'),
    ]);
    my $tf = Trustforge->new(ua => $ua);
    my $r  = $tf->decide({ action => 'fs.read' });
    is $r->{decision}, 'allow', 'allow';
    is scalar(@{ $ua->{history} }), 1, 'one request issued';
    my $req = $ua->{history}[0];
    is $req->method, 'POST', 'POST';
    like $req->uri->as_string, qr{/v1/decide$}, 'path';
    like $req->content, qr/fs\.read/, 'body has action';
};

subtest 'decide: 503 -> daemon-unavailable' => sub {
    my $ua = MockUA->new(queue => [ mock_response(503, 'boom') ]);
    my $tf = Trustforge->new(ua => $ua);
    eval { $tf->decide({ action => 'fs.read' }) };
    my $err = $@;
    ok $err, 'died';
    is ref($err) eq 'HASH' ? $err->{kind} : '', 'daemon-unavailable',
        'kind';
};

subtest 'decide: 401 -> daemon-rejected' => sub {
    my $ua = MockUA->new(queue => [ mock_response(401, 'no') ]);
    my $tf = Trustforge->new(ua => $ua);
    eval { $tf->decide({ action => 'fs.read' }) };
    my $err = $@;
    is ref($err) eq 'HASH' ? $err->{kind} : '', 'daemon-rejected',
        'kind';
    is ref($err) eq 'HASH' ? $err->{code} : 0, 401, 'code';
};

subtest 'decide: passes admin_token bearer header' => sub {
    my $ua = MockUA->new(queue => [
        mock_response(200,
            '{"decision":"allow","reason":"","proof_id":"p"}'),
    ]);
    my $tf = Trustforge->new(ua => $ua, admin_token => 'k1');
    $tf->decide({ action => 'fs.read' });
    my $req = $ua->{history}[0];
    is $req->header('Authorization'), 'Bearer k1', 'auth header';
    is $req->header('Content-Type'),  'application/json', 'json content type';
};

done_testing;
