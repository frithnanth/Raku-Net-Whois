use v6.d+

unit class Net::Whois:ver<0.0.2>:auth<zef:FRITH>;

subset IP of Str is export where * ~~ /^ [ (\d ** 1..3) <?{ $/[*-1][*-1] < 256 }> ] ** 4 % '.' $/;
subset Domain of Str is export where {
                                        $_.chars ≤ 253 &&
                                        $_ ~~ / ^ \d* [[<[a..z-]>+ \d*]+ \d*]+ % '.' $/
                                     }

multi method query(Str:D $who where { $_ ~~ IP | Domain or die 'Not a valid IP or domain name' },
                   Str:D $server,
                   Bool :$raw!
                   --> List) {
  self!connection($who, $server);
}

multi method query(Str:D $who where { $_ ~~ IP | Domain or die 'Not a valid IP or domain name' },
                   Str:D $server,
                   Bool :$multiple
                   --> Hash) {
  my @answers = self!connection($who, $server);
  my %answers;
  for @answers -> $answer {
    next if $answer.starts-with: '%'|'#';
    next unless $answer.contains: ':';
    my ($key, $value) = $answer.split(':', 2)».trim;
    if $multiple {
      %answers{$key}.push: $value;
    } else {
      %answers{$key} = $value;
    }
  }
  if %answers<ReferralServer>:exists {
    %answers<ReferralServer> .= substr: 8 if %answers<ReferralServer>.starts-with: 'whois://';
    %answers = self.query: $who, %answers<ReferralServer>, :$multiple;
  }
  %answers;
}

multi method query(Str:D $who where { $_ ~~ IP | Domain or die 'Not a valid IP or domain name' },
                   *@servers,
                   Bool :$multiple,
                   Bool :$raw
                   --> Hash) {
  my %answers;
  for @servers -> $server {
    if $raw {
      %answers{$server} = self.query: $who, $server, :raw;
    } else {
      %answers{$server} = self.query: $who, $server, :$multiple;
    }
  }
  %answers;
}

method !connection(Str:D $who, Str:D $server --> List) {
  my $sock = IO::Socket::INET.new: :host($server), :port(43), :encoding('utf8-c8');
  $sock.print: "$who\n";
  my @answers;
  for $sock.lines -> $line {
    @answers.push: $line;
  }
  $sock.close;
  @answers;
}

=begin pod

=head1 NAME

Net::Whois - Raku interface to the Whois service

=head1 SYNOPSIS

=begin code :lang<raku>

use Net::Whois;

my Net::Whois $w .= new;
my %h = $w.query: $who, $using;
for %h.kv -> $k, $v { say "$k => $v[*]" }

=end code

=head1 DESCRIPTION

Net::Whois is an interface to the Whois service

This is a very simple module that does what I just happened to need.

=head3 new()

The constructor takes no arguments.

=head3 multi method query(Str:D $who where { $_ ~~ IP | Domain or die 'Not a valid IP or domain name' },
                   Str:D $server,
                   Bool :$raw!
                   --> List)
=head3 multi method query(Str:D $who where { $_ ~~ IP | Domain or die 'Not a valid IP or domain name' },
                   Str:D $server,
                   Bool :$multiple
                   --> Hash)
=head3 multi method query(Str:D $who where { $_ ~~ IP | Domain or die 'Not a valid IP or domain name' },
                   *@servers,
                   Bool :$multiple,
                   Bool :$raw
                   --> Hash)

The first form of the method looks for the B<$who> domain, using the chosen B<$server> and returns a B<List> of values.
If the B<:$raw> flag is used then the result is returned verbatim.

The second form returns a B<Hash> of the whois fields. The whois output may consist of several sections; if the
B<:$multiple> flag is used the values of the same-named field are concatenated into the same value string.

The third form takes a list of servers to query. It returns a B<Hash> whose keys are the name of the server and the
values are the hashes returned by the second form of the method, or the lists returned by the first form of the method
if the B<:$raw> flag has been used.

=head1 Installation

To install it using zef (a module management tool):

=begin code
$ zef install Net::Whois
=end code

=head1 AUTHOR

Fernando Santagata <nando.santagata@gmail.com>

=head1 COPYRIGHT AND LICENSE

Copyright 2023 Fernando Santagata

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

=end pod
