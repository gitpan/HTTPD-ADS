#! /usr/bin/perl
use Errno qw(EAGAIN);
use IO::Socket::UNIX;
use Carp;
use Net::IP::Route::Reject;

my $target_user ="dhudes";
my $ipv4octetregex = "([0-1]??(1,2)|2[0-4]|25[0-5])";
my $ipv4regex = "/^".$ipv4octetregex."\.".$ipv4octetregex."\.".$ipv4octetregex."\.".$ipv4octetregex."\$/o";
study $ipv4regex;
my $fifo = "/tmp/BlackList";
if(-e $fifo){
  die "socket file present and I can't delete it" if((unlink $fifo) !=1);
}
my $message;


my $listen = IO::Socket::UNIX->new(Local=>$fifo, Listen=>0) || die "$!"; #per io_unix.t of IO::Socket::UNIX
my $rv = chown((getpwnam($target_user))[2,3],$fifo);#adapted from p691 of _Programming Perl_,3rd ed.
print "socket set blocking, was ".$listen->blocking(1);#1 is TRUE
#my $oldtimeout = $listen->timeout(3600);
#print "\ntimeout set, was ".(defined $oldtimeout? $oldtimeout: "undefined\n");
my @ipaddr;
my $sock;
while (1) {
  $sock = $listen->accept();
  if(defined $sock){
	$message= $sock->getline;
	if(!defined $message){
		my $time=scalar localtime;
		print  "$time: socket problem $! no message\n";
		next;
	}
  	@ipaddr = grep $ipv4regex, $message; #strip out anything that doesn't belong in an ip addres
  	Net::IP::Route::Reject->add( $ipaddr[0]);
 }
}


