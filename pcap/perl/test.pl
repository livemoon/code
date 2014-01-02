#!/usr/bin/perl

use strict;
use warnings;

use Net::Pcap;
#use NetPacket;
use NetPacket::IP;
use NetPacket::Ethernet qw(:strip);

my $file = "test.cap";
my $file = "/var/log/pflog";
my $err = '';

my $dev = Net::Pcap::lookupdev(\$err);
print "Dev is $dev\n";

#my @dev_list = Net::Pcap::findalldevs(\$err);
#print "Dev list is @dev_list\n";

my $pcap = Net::Pcap::open_offline($file, \$err)
    or die "Can't open file ... $err\n";
Net::Pcap::loop($pcap, -1, \&process_pkt, "");
Net::Pcap::close($pcap);

sub process_pkt {
    my($user_data, $hdr, $pkt) = @_;
    
    my $ether_data = NetPacket::Ethernet::strip($pkt);
    my $ip = NetPacket::IP->decode($ether_data);
#    my $tcp = NetPacket::TCP->decode($ip->{'data'});

    print("$ip->{src_ip} --> $ip->{dest_ip}\n");
}
