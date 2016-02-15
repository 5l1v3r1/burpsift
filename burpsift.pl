#!/usr/bin/perl
########################################################################
# Functional Description: 
# burpsift.pl is developed to parse Burp log. It's designed to replace burpsift.py, as the original
# python script is both lack of maintenance and too slow. In addition, bug fixes and new features such 
# as filtering would be easier to support going forward.
# For more detail, run the following command:
# 			$ burpsift.pl -h
########################################################################
# Developed by:		Yang Li
########################################################################
# Change History: 
#
# Last modification: 			08/08/2011
#	Version		0.1g
#       08/08/2011      Add support to SOAP message detection.
#       08/05/2011      Add support to iframe element detection.
#       08/03/2011      Add support to Server Side Includes (SSI) element detection.
#       07/19/2011      Bug fix of case handling for variable "recording" be negative.
#	07/19/2011	Bug fix of missing multi-lines C language style comment pattern "/* - */" as suggested by Moshe
#	07/11/2011	Basic development is finished. The functionalities are now similiar to burpsift.py script, 
#			in additional to the desired filter feature.
########################################################################
use Getopt::Long qw/:config bundling_override no_ignore_case/;
########################################################################
## Program Argument Check
########################################################################
my $ver="0.1g", $author="Yang Li";					# Program Version and Author
my $verbose;								# Verbose mode
my %opts;
GetOptions(
	\%opts,
	'help|h|?' => sub { &print_help and exit 0; },			# Print help
	'version|v:s' => sub { &print_banner; exit 0;},	                # Print program version information
	'input|i:s',               					# Mandatory Burp log file as program input	
	'output|o:s',               					# Optional, program output result files' prefix
	'filter|l:s',                                     		# Optional, URL filter to narrow down the relevant application only
	'verbose+' => \$verbose,					# Optional, program verbose mode for debugging
	'vv+' => \$verbose,						# Same as "-verbose", abbreviation "-vv"
);				
my $f_output=defined $opts{output} ? $opts{output} : 'output';		# Default output files' prefix
my $f_input=$opts{input};
my $regex_filter_title=defined $opts{filter} ? $opts{filter} : '.';
unless ($f_input) { &print_help and exit 1; }				# Burp log input file is mandatory
########################################################################
# Main Program
########################################################################
my %BURPLOG;
my $file_size=(-s $f_input);
my %FOUT = (urls=>$f_output."_URLs.txt", setcookie=>$f_output."_setcookies.txt", auth=>$f_output."_authentication.txt",
           meta=>$f_output."_metatags.txt", server=>$f_output."_server.txt", Xheaders=>$f_output."_Xheaders.txt", mailto=>$f_output."_mailto.txt",
           hidden=>$f_output."_hiddenfields.txt", disabled=>$f_output."_disabledfields.txt", axo=>$f_output."_ActiveXObjects.txt",
           single=>$f_output."_CommentsSingleLn.txt", status=>$f_output."_StatusCodes.txt", multi=>$f_output."_CommentsMultiLn.txt", 
           objs=>$f_output."_objects.txt", applets=>$f_output."_applets.txt", ssi=>$f_output."_SSI.txt", iframe=>$f_output."_iframes.txt",
           SOAP=>$f_output."_SOAPs.txt"
);
my %REGEX = (setcookie => "\^Set\-Cookie\:\\s+",
             auth => "(\^WWW-Authenticate\:\\s+|password)",
             meta => "\<meta\\s+",
             server => "\^server\:\\s+",
             Xheaders => "\^x\-",
             mailto => "mailto\:",
             hidden => "\\<input\\s+type\\s*=\\s*(\'|\")*\\s*hidden",
             disabled => "\\<input\\s+(.)*\\s+disabled\\s*=\\s*(\'|\")disabled(\'|\")",
             axo => "ActiveXObject",
             single => "^(\\s|\\t)*\/\/",
             status => "^HTTP\\/1\\.(0|1)\\s+\\d{3}\\s+[A-Za-z]+",
             multi_s => "(\\<\\!--|^(\\s|\\t)*\\/\\*)", multi_e => "(--\\>|\\*\\/)",
             obj_s => "\\<object\\s*", obj_e => "\\<\\/object\\>",
             applet_s => "\\<applet\\s*", applet_e => "\\<\\/applet\\>",
             ssi_s => "\\<\\!--\\#(.)*=(.)*", ssi_e => "--\\>",
             iframe_s => "\\<iframe(.)*", iframe_e => "\\<\\/iframe\\>",
             SOAP_s => "\\<SOAP(.)*\:", SOAP_e => "\\<\\/SOAP(.)*\:\\>"
);

&print_banner;
print "Processing Burp log file: $f_input\nTotal input file size: $file_size bytes\n\n";
parse_burp_log ($f_input,$regex_filter_title);
if ($verbose) { print "Print out the filtered Burp log:\n\n"; &print_burp_log; }

sift_urls ($FOUT{urls});
sift_full_text($FOUT{setcookie},$REGEX{setcookie});
sift_full_text($FOUT{auth},$REGEX{auth});
sift_one_liner($FOUT{meta},$REGEX{meta});
sift_one_liner($FOUT{server},$REGEX{server});
sift_one_liner($FOUT{Xheaders},$REGEX{Xheaders});
sift_one_liner($FOUT{mailto},$REGEX{mailto});
sift_one_liner($FOUT{hidden},$REGEX{hidden});
sift_one_liner($FOUT{disabled},$REGEX{disabled});
sift_one_liner($FOUT{axo},$REGEX{axo});
sift_one_liner($FOUT{single},$REGEX{single});
sift_one_liner($FOUT{status},$REGEX{status});
sift_element($FOUT{multi},$REGEX{multi_s},$REGEX{multi_e});
sift_element($FOUT{objs},$REGEX{obj_s},$REGEX{obj_e});
sift_element($FOUT{applets},$REGEX{applet_s},$REGEX{applet_e});
sift_element($FOUT{ssi},$REGEX{ssi_s},$REGEX{ssi_e});
sift_element($FOUT{iframe},$REGEX{iframe_s},$REGEX{iframe_e});
sift_element($FOUT{SOAP},$REGEX{SOAP_s},$REGEX{SOAP_e});

print "\nAll processings are completed successfully!\n";
exit(0);

##############################################################################################################
# Functions & Subroutines
##############################################################################################################
sub print_help () {
#
# print help / hint for average user
#
        my $ph = (split /[\\|\/]/, $0)[-1];
        &print_banner;
	print <<HELP
Functional Description:
burpsift.pl is developed to sift out the Burp log for the grains of gold. It's designed to replace the original burpsift.py, as the python script is both too slow and lack of maintenance.
	
Syntax:
	\$ $ph ?|-h|--help
			-h|?|help		Print help message
			-i|input		Mandatory Burp log file as program input
			-o|output		Optional program output files' prefix
			-l|filter		Optional, URL filter to narrow down the relevant application only.
			-vv|verbose		Program in verbose mode
			-v|version		Program version	

Usage Example:
To sift out the Burp log 'myapp_burp_log' for application 'www.myapp.com', and save outcome to files with prefix 'myapp_output':
          \$ \.\/$ph -i myapp_burp_log -o myapp_output -l myapp.com
HELP
}

sub parse_burp_log () {
#
## Parse the Burp log file once. Filtered entries are recorded into a hash table %BURPLOG for later usage.
#
	my $f_input=$_[0];
	print "Parsing Burp log file $f_input ...";
	my $regex_filter_title=$_[1];
	my ($title, @request, @response, $num_ln, $url_base, $url_path, $url);
	my $cnt_recording=0;
	my $regex_sep_main = "^\\={54}";
	my $regex_title_burp="^\\d{1,2}:\\d{1,2}:\\d{1,2}\\s+(AM|PM)\\s+http(s)*:\\/\\/";
	my $regex_http_request="^(GET|POST|HEAD|OPTIONS|PUT|DELETE|TRACE|CONNECT)\s+";
	open (IN,"<", $f_input) || die "Can't open the input file $f_input: $!\n";
	while (<IN>) {
		chomp;
		$num_ln++;
		my $line=$_;
		if ($verbose) { print "Processing Burp log file $f_input line number $num_ln ...\n"; }
		if ( /$regex_title_burp/i) {
			# Save recorded burp log entry from the previous cycle into the data structure
			if ($title =~ /$regex_filter_title/i) {
				my $key=$tile." | ".$url;							
				# Need this converstion as @request and @response are passed by reference back to outer scope
				my @req=@request;
				my @res=@response;
				$BURPLOG{$key}{title}=$title;
				$BURPLOG{$key}{url}=$url;
				$BURPLOG{$key}{request} = \@req;
				$BURPLOG{$key}{response} = \@res;
			}
			# Reset recording variables and counter
			$url_path="";
			$url_base="";
			$url="";
			@request="";
			@response="";
			$cnt_recording=1;
			# Start recording new Burp log entry
			$title=$line;
			my @T=split(/\s+/,$title);
			$url_base=$T[2]; 
			unless($url_base =~ /http/) { die "Debugging info: problem extracting base URL from the Burp log:  file - $f_input, line number - $num_ln,  base URL - $url_base\n"; } # Debugging checkpoint if necessary
			next;
		} elsif ( /$regex_sep_main/i) { 
			$cnt_recording++;  
			next;
		}
		if ($cnt_recording==2) { 
			push @request,$_;
			if (/^(GET|POST|HEAD|OPTIONS|PUT|DELETE|TRACE|CONNECT)\s+/i) {
				my @Req=split(/\s+/,$line);
				$url_path=$Req[1];
			}
			$url=$url_base.$url_path;
			next;
		} elsif ($cnt_recording==3) {
			push @response,$_;
			next;
		} else {
			next;
		} 
	}
	# Catch the last Burp log entry before exit
	if ($title =~ /$regex_filter_title/i) {
		my @req=@request;
		my @res=@response;
		my $key=$title." | ".$url;
		$BURPLOG{$key}{title}=$title;
		$BURPLOG{$key}{request} = \@req;
		$BURPLOG{$key}{response} = \@res;
	}
	close (IN);
	print " Done!\n";
}

sub print_burp_log () {
#
## Print out the full hash table %BURPSIFT
#
	print "\n\nPrint out the filtered Burp log ....\n";
	foreach my $key ( sort keys %BURPLOG ) {
		print "="x54,"\n";
                print "$key\n", "="x54;
		foreach (@{$BURPLOG{$key}{request}}) { print "$_\n"; }
		print "="x54;
		foreach (@{$BURPLOG{$key}{response}}) { print "$_\n"; }
		print "="x54,"\n"x4;
	}
}

sub sift_urls () {
#
## Spit out the visited URLs from the hash table. And save it to a seperate output file
#
	open (OUT,">",$_[0]) || die "Can't open file $f_output: $!\n";
	foreach my $key (sort keys %BURPLOG) {	print OUT "$BURPLOG{$key}{url}\n"; }
	close(OUT);
	if (-s $_[0]) { print "Sift out file $_[0] ... Done!\n";} else { unlink $_[0]; }	
}

sub sift_full_text () {
#
## Spit out the http request/response full txt based on the regular expression. And save them to a seperate output file.
#
	my $f_output=$_[0];
	open (OUT,">",$f_output) || die "Can't open file $f_output: $!\n";
	foreach my $key (sort keys %BURPLOG ) {	
		my $fnd=0;
		foreach (@{$BURPLOG{$key}{response}}) { if (/$_[1]/i) { $fnd++;}	}
		if ($fnd) {
			print OUT "\n"x3, "="x54, "\n";
			print OUT "$BURPLOG{$key}{title}\n", "="x54,"\n";
			foreach (@{$BURPLOG{$key}{request}}) { print OUT "$_\n"; }
			print OUT "="x54;
			foreach (@{$BURPLOG{$key}{response}}) { print OUT "$_\n";}
			print OUT "="x54;
		}
	}
	close(OUT);
	# Remove file if file size is zero
	if (-s $f_output) { print "Sift out file $f_output ... Done!\n"; } else { unlink $f_output; }	
}

sub sift_one_liner () {
#
## Spit out the interesting one-liners based on the regular expression. And save them into a seperate output file.
#
	my $f_output=$_[0];				
	open (OUT,">",$f_output) || die "Can't open file $f_output: $!\n";
	foreach my $key (sort keys %BURPLOG ) {	
		my $fnd=0;
		foreach (@{$BURPLOG{$key}{response}}) { 
			if (/$_[1]/i) {
				$fnd++;
			}
		}
		if ($fnd) {
			my @T=split(/\|/,$key);
			print OUT "\n"x3, "="x54, "\n";
			print OUT "$BURPLOG{$key}{title}\n", "="x54, "\n";
			print OUT "Full URL - $T[1]\n\n";
			foreach (@{$BURPLOG{$key}{response}}) { 
				if (/$_[1]/i) { 
					my $line=$_;
					$line=~s/^(\s|\t)+//g;
					print OUT "$line\n";
				}
			}
			print OUT "="x54, "\n";
		}
	}
	close(OUT);
	if (-s $f_output) { print "Sift out file $f_output ... Done!\n"; } else { unlink $f_output; }			
}

sub sift_element () {
#
## Spit out the strictly defined html element based on the start and end tag. And save them into a seperate output file.
#
	my $f_output=$_[0];				
	open (OUT,">",$f_output) || die "Can't open file $f_output: $!\n";
	foreach my $key (sort keys %BURPLOG ) {	
		my $fnd=0;
		foreach (@{$BURPLOG{$key}{response}}) { 
			if (/$_[1]/i) { $fnd++; }
		}
		if ($fnd) {
			my @T=split(/\|/,$key);
			print OUT "\n"x3, "="x54, "\n";
			print OUT "$BURPLOG{$key}{title}\n", "="x54,"\n";
			print OUT "Full URL - $T[1]\n\n";
			my $recording=0;
			foreach (@{$BURPLOG{$key}{response}}) { 
				my $line=$_;
				if ($line =~ /$_[1]/i) { $recording++;	}
				if ($recording > 0) { print OUT "$line\n";	}
				if (($line =~ /$_[2]/i) && ($recording > 0) ) { $recording--;	}
			}
			print OUT "="x54, "\n";
		}
	}
	close(OUT);
	if (-s $f_output) { print "Sift out file $f_output ... Done!\n"; } else { unlink $f_output; }	
}

sub print_banner () {
#
## Print program header in the ascii art format - you know graphic count :-)
#
	print "o"x80,"\n";
	print "@@@@@@@   @@@  @@@  @@@@@@@   @@@@@@@    @@@@@@   @@@  @@@@@@@@  @@@@@@@     
@@@@@@@@  @@@  @@@  @@@@@@@@  @@@@@@@@  @@@@@@@   @@@  @@@@@@@@  @@@@@@@     
@@!  @@@  @@!  @@@  @@!  @@@  @@!  @@@  !@@       @@!  @@!         @@!       
!@   @!@  !@!  @!@  !@!  @!@  !@!  @!@  !@!       !@!  !@!         !@!       
@!@!@!@   @!@  !@!  @!@!!@!   @!@@!@!   !!@@!!    !!@  @!!!:!      @!!
!!!@!!!!  !@!  !!!  !!@!@!    !!@!!!     !!@!!!   !!!  !!!!!:      !!!       
!!:  !!!  !!:  !!!  !!: :!!   !!:            !:!  !!:  !!:         !!:       
:!:  !:!  :!:  !:!  :!:  !:!  :!:           !:!   :!:  :!:         :!:       
 :: ::::  ::::: ::  ::   :::   ::       :::: ::    ::   ::          ::       
:: : ::    : :  :    :   : :   :        :: : :    :     :           : \n";
	print "\nburpsift.pl version: $ver. Developed by $author\n", "o"x80, "\n"x2;
}
