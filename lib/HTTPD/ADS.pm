package HTTPD::ADS;
use strict;
use warnings;
use vars qw ($VERSION @ISA );
$VERSION     = 0.2;
use base qw/ Class::Constructor Class::Accessor /;
use HTTPD::ADS::DBI;
use CLASS;
use CGI::Carp qw(cluck  carpout);
use IO::Socket::UNIX;
use Date::Calc qw(Normalize_DHMS Add_Delta_YMDHMS System_Clock Today_and_Now Gmtime );

use constant MAX_REQUEST_STRING_LENGTH =>64;
use constant MAX_REQUEST_STRING_COLUMN => 63;
BEGIN {
    #this is supposed to have been done by use base...
    use vars qw ( @ISA);
    require Class::Accessor;
    require Class::Constructor;
    push @ISA, 'Class::Accessor','Class::Constructor';
}
########################################### main pod documentation begin ##
# Below is the documentation for this module.


=head1 NAME

HTTPD::ADS - Perl module for Attack Detection and Prevention System using Data Mining.

=head1 SYNOPSIS

    use HTTPD::ADS



=head1 DESCRIPTION

    Attack Detection System


=head1 USAGE



=head1 BUGS



=head1 SUPPORT



=head1 AUTHOR

    Dana Hudes
    CPAN ID: DHUDES
    dhudes@hudes.org
  http://www.hudes.org

=head1 COPYRIGHT

    This program is free software licensed under the...

    The General Public License (GPL)
    Version 2, June 1991

    The full text of the license can be found in the
    LICENSE file included with this module.


=head1 SEE ALSO

    perl(1).

=cut

############################################# main pod documentation end ##

my @Accessors = qw (
			IDSDatabase
			IDSDataUser
			IDSDataPassword
			IDSEventsThresholdLevel
			IDSTimeWindowSize
			normalizedIDSTimeWindowSize
			msgQ

			);
CLASS->mk_accessors(@Accessors);
CLASS->mk_constructor(
                      Name => 'new',
                      Auto_Init => \@Accessors,
                      Init_Methods => '_init',
		     );
################################################ subroutine header begin ##

=head2 sample_function

    Usage     : How to use this function/method
    Purpose   : What it does
    Returns   : What it returns
    Argument  : What it wants to know
    Throws    : Exceptions and other anomolies
    Comments  : This is a sample subroutine header.
    : It is polite to include more pod and fewer comments.

    See Also   :

=cut

################################################## subroutine header end ##

sub gmttimestamp  {
    my ($year,$month,$day,$hour,$min,$sec)= Gmtime();
    return "$year-$month-$day $hour:$min:$sec";
}

sub pgtimewindow {
    my $self = shift;
    my @timestamp= Gmtime;
    #    my ($year,$month,$day,$hour,$min,$sec,$doy,$dow,$dst)= Gmtime();
    my $ref =  $self->normalizedIDSTimeWindowSize;
    $ref = $$ref;
    my ($target_year,$target_month,$target_day,$target_hour,$target_min,$target_sec) =
	Add_Delta_YMDHMS(@timestamp[0..5], @$ref);
    my $result = "$target_year-$target_month-$target_day $target_hour:$target_min:$target_sec";
}
sub _init {
    #_init sets up the db connection and prepares the SQL we'll need for insert and retrieve
    my $self = shift;


    $self->IDSTimeWindowSize(defined $self->IDSTimeWindowSize? -$self->IDSTimeWindowSize: -300);
    $self->IDSEventsThresholdLevel(10) unless defined $self->IDSEventsThresholdLevel;
    $self->normalizedIDSTimeWindowSize( \[0,0,Normalize_DHMS(0,0,0,$self->IDSTimeWindowSize)] );


}
    #we need a whitelist. I think check it before recording events i.e. refuse to store
    #events about whitelisted hosts
    sub event_recorder {
	# put the status, ip address and time into database. If time isn't supplied, use the postgresql now() function
	#If the status is 401, see if we should blacklist this ip address
	my $self=shift;
	my %args=@_;
	my ($eventrecord,$hostentry,$arg_string,$username,$request_string,$whitelist_entry);
	my $max_request_length=64; #not max column number, which is one less 
	#in future it may well be more optimal to keep the whitelist in
	#memory in a Patricia Trie. Initially it is more transparent
	#to keep it in an SQL table.  In future it may be desirable
	# to store it in the dbms and load it all at start into a Patricia Trie.
	#or it might be better to make a separate module containing
	#a Whitelist class with the whitelist as a class variable.


	$args{time}=$self->gmttimestamp unless defined $args{time};
	confess "no ip address supplied" unless defined $args{ip};
	confess "no status supplied" unless defined $args{status};
	$whitelist_entry = HTTPD::ADS::Whitelist->retrieve($args{ip});
	if (!$whitelist_entry) {
	    substr($args{request},MAX_REQUEST_STRING_COLUMN)='' if ((length $args{request})  > MAX_REQUEST_STRING_LENGTH); #a clever way to trim to maximum length	
	    $hostentry= HTTPD::ADS::Hosts->find_or_create(ip => $args{ip});
	    #      $arg_string = '-' unless (defined $args{arg_string});
	    #     $arg_string = HTTPD::ADS::Arg_strings->find_or_create({arg_string => $args{arg_string}});

	    $request_string = HTTPD::ADS::Request_strings->cached_find_or_create({request_string =>$args{request}});
	    $username = HTTPD::ADS::Usernames->cached_find_or_create({username => $args{user}});
	    $eventrecord = HTTPD::ADS::Eventrecords->create(
							    {
							     ts =>$args{time},
							     ip=> $args{ip},
							     status => $args{status},
							     userid => $username->userid,
							     requestid => $request_string->requestid,
							     #					     argid => $arg_string->argid

							    }
							   );

	    $self->analyze401(\%args) if($args{status}== 401);
	} else {
	    use Sys::Syslog;
	    my $program = $ARGV[0];
	    openlog("$program $$",'pid','local6');
	    syslog('warning',"%s event received for whitelisted host %s",$args{status},$args{ip});
	    closelog;
	}
    }

sub analyze401 {
    my ($self,$args) = @_;
    #Class::DBI::AbstractSearch format which is to say SQL::AbstractSearch  WHERE clause
    my @events;
    my $eventcount;
    @events=HTTPD::ADS::Eventrecords->search_where( 
						   {
						    ip => $$args{ip}, #=
						    ts =>{'>=',$self->pgtimewindow}},
						   {
						    order =>'ts'}
						  );
    $eventcount = $#events + 1;
    $self->blacklist(
		     ip=>$$args{ip}, first_event => $events[0]->get('eventid'),block_reason => 401 
		    )
	if ($eventcount >= $self->IDSEventsThresholdLevel);
  
}
{
    my %blocked_list;
    sub blacklist {
	my ($self,%args) = @_;
	unless ($blocked_list{$args{ip}}++ > 0) {
	    my $fifo = "/tmp/BlackList";
	    my $Blacklisted;
	    die "socket file $fifo present and I can't write to it" unless(-w $fifo) ;
	    my $sock = IO::Socket::UNIX->new(Peer => $fifo) or confess "$!";
	    $sock->print($args{ip}); #we use line-oriented i/o, its simpler...
	    $args{active}=  'true'; #true...
	    $args{blocked_at}=$self->gmttimestamp;	
	    $Blacklisted = HTTPD::ADS::Blacklist->create(\%args) ;
	}
    }
}



1; #this line is important and will help the module return a true value
__END__






