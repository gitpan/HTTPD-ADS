use Module::Build;
# See perldoc Module::Build for details of how this works

Module::Build->new
    ( module_name     => 'HTTPD::ADS',
      license         => 'gpl',
      requires => {
	Class::DBI =>'0.94',
	Class::DBI::AbstractSearch =>'0.03',
	  CLASS =>'0.91',
	  CGI::Carp =>'1.26',
	  IO::Socket::UNIX =>'1.20',
	  Date::Calc =>'5.3',
	  Class::Accessor =>'0.18',
	  Class::Constructor =>'1.0.0',
	  Class::DBI::Pg =>'0.03',
	Net::IP::Route::Reject =>'0',
	HTTPD::Log::Filter =>'1.07',
	Compress::Zlib =>'1.22'
	},
      script_files =>[ "DefenseServer.pl LogReader.pl"],
      sign =>1
    )->create_build_script;
