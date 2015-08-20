package SSO::WSSO;

use strict;
use warnings;
use Apache2::RequestRec ();
use Apache2::Const -compile => qw(OK DECLINED SERVER_ERROR NOT_FOUND REDIRECT); 

		
sub handler {
	my $r		= shift;

	my $ssoSession = getSSOCookie( $r );

	if( $ssoSession eq '' ){
		my  $matchPublic = $r->dir_config('WSSO_APP_PUBLIC') ;

		if( $r->uri !~ /$matchPublic/o  ){
		      $r->uri($r->dir_config('REDIRECT_URL'));
		}
		return Apache2::Const::DECLINED;
	};

	my $ssoAuthenticationURL=$r->dir_config('WSSO_SSO_AUTH_URL');
	if( $r->uri !~ /$ssoAuthenticationURL/o ){
		return Apache2::Const::DECLINED;
	};	

	#	SSO Server
	#	It is a service which take the cookie as input and returns "username" and "password"
	#
	my $urlsessione = $r->dir_config('WSSO_URL_SSO') . $ssoSession;
	my $asSession = getSSOSession( $urlsessione );
	my $username=$asSession->{'username'};
	my $password=$asSession->{'password'};


	#	contextRoot of the application
	my $url=''; my $args='';
	my $contextRoot='';
       	if( $r->uri =~ /^(\/[^\/]+)\//o ){
		$contextRoot=$1;
	}

	# 	verify if  contextRoot is a  j2ee or  perl based application.
	# 	Then, change url for authentication on underlyng systems accordingly.
	#
	my $matchJ2ee=$r->dir_config('WSSO_APP_J2EE');
	
	if( $contextRoot =~ /$matchJ2ee/o ){
        $url=qq|$contextRoot/j_security_check|;
		$args=qq|j_username=$username&j_password=$password|;
    }else{
		$url=qq|$contextRoot/auth.pl|;
		$args=qq|PERL_USERNAME=$username&PERL_PASSWORD=$password|;
	}

        $args .= '&'. $r->args;
	
	$r->uri($url);
	$r->args($args);

	return Apache2::Const::DECLINED;
}


sub getSSOSession{
	my ($urlsession) = @_;
	my %as;

	use LWP::UserAgent;
	my $ua = new LWP::UserAgent;
	$ua->agent("AgentName/0.1 " . $ua->agent);
	my $req = new HTTP::Request GET => $urlsession;
	$req->content_type('application/x-httpd-cgi');
	$req->content('match=www&errors=0');
	my $res = $ua->request($req);

	if ($res->is_success){
		my (@rows,$k,$v );
		@rows = split( /\n/, $res->content );
		foreach my $r(@rows) {
			chomp($r);
			($k,$v)=split(/=/, $r);
			$as{$k}=$v;
		}
	}
	return \%as;
}

				
				
sub getSSOCookie {
	my ($r) = @_;
	my $cookie = $r->headers_in->{Cookie} || '';
	my $name = $r->dir_config('WSSO_COOKIE_SSO') || '';

	my $as = getCookies( $cookie ); 
	my $out = $as->{ $name } || '';
	return $out;
}

sub getCookies{
	my ($strCookie) = @_;
	my %as;
	if( $strCookie eq '' ) {return \%as;}

	$strCookie =~ s/^Cookie:\s*//;
	my @cookies = split( /;\s*/, $strCookie );
	foreach my $c( @cookies ) {
		my ($k, $v) = split(/=/, $c );
		$as{$k}=$v;
	}
	return \%as;
}



1;
