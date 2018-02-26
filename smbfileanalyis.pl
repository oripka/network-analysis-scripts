#!/usr/bin/perl
use CGI ':standard';
use GD::Graph::bars;

if (@ARGV != 1){
	print("Need to give pcap file as arguement\n");
	exit 1;
}

$pcap = $ARGV[0];

@files=`tshark -r \"$pcap\" -Tfields -e smb.file -e smb.data_len_low -Eseparator=# | sort `;

$current = trim($files[0]);
@cur = split(/\#/, $current);
$current = @cur[0];
$cnt = 0;

@data;
@dfiles;
@dfcnt;
foreach(@files){
	$line = trim($_);
	@factors = split(/\#/, $line);

	if (trim($factors[1]) eq "" ){
		$factors[1] = 0;
	}

	if ($current eq $factors[0]){
		$result = $result + $factors[1];
#		print ("Analysing $line, $factors[1] bytes, $cnt times\n");
		$cnt = $cnt + 1;
	}else{
		print "|$current|$result|$cnt\n";
		push(@dfiles, $current);
		push(@dfcnt, $cnt);

		$current = $factors[0];
		$result = 0;
		$cnt = 1;
		$result = $result +  $factors[1];
	}
}

my @data = (\@dfiles,\@dfcnt);

my $mygraph = GD::Graph::bars->new(2048, 2048);
$mygraph->set(
    title       => 'SMB Files Transfers',
) or warn $mygraph->error;

$mygraph->set( x_labels_vertical => 1 );

my $myimage = $mygraph->plot(\@data) or die $mygraph->error;

open (MYFILE, '>>chart.png');
print MYFILE $myimage->png;
close (MYFILE);

sub trim($)
{
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}
