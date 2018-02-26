#!/usr/bin/perl

use strict;
use Fcntl;

sub help(){
	print STDERR <<STOP

./tshark-match-list.pl -l listfile -R displayfilter

./tshark-match-list.pl -l "list.txt" -R "dns.qry.name="
STOP
}

my $lfile=$ARGV[1];
my $filter=$ARGV[3];

my $fstring = "";

if($lfile ne ""){

	sysopen(NAMES,$lfile, O_RDONLY)
		or die "Couldn't open file for reading: $!\n";
		
	my $first="yes";
	my $val = "";
	while (<NAMES>){
		chomp $_;
		if($filter =~ /contains/){
			$val = "\\\"$_\\\"";
		}else{
			$val=$_;
		}
	
		if($first ne "yes"){
			$fstring = "$fstring or $filter $val";
		}else{
			$fstring = "$filter $val";
			$first="no";
		}
	}
}

print "$fstring\n";
exit 0;
