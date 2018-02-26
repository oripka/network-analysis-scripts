#!/usr/bin/perl

sub help() {
print STDERR <<STOP
This script calculates the total amount of bytes transfered over tcp for the
selected display filter.

WARNING: this script also counts retransmissions retransmissions. And
will certainly fail, if packets got lost.

	Usage: 
		./tcp-payload-calc.sh -R display-filter -r filename.pcap
		./tcp-payload-calc.sh -R "ftp-data " -r "ftpdatatrace.pcap"
STOP
}

sub trim($)
{
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

if (@ARGV != 4){
  &help();
  exit -1;
}

my $filt = $ARGV[1];
my $file = $ARGV[3];

my $tshark = "tshark -2 -Tfields -e tcp.len -r \"$file\" -R \"$filt\"";
my $cmd = "$tshark | sort | uniq -c";
my $line = "";
my $result = 0;
#print "Executing:\n\t$cmd\n";

@out = `$cmd`;

foreach(@out){
	$line = trim($_);
	@factors = split(/ /, $line);
	$result = $result + ( $factors[0] * $factors[1] );
	print "Transfered $factors[0] packets with $factors[1] bytes\n";
}

my $kb=$result/1024;
my $mb=$kb/1024;
my $gb=$mb/1024;

print "-------\nTotal amount of bytes transfered: $result Bytes";

if($result > 1024*10){
	print ", $kb KB";
}
if($result > 1024*1024*10){
	print ", $mb MB";
}
if($result > 1024*1024*1024*10){
	print ", $gb GB";
}
print "\n";
