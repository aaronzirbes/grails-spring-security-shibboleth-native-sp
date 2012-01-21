security {
	shibboleth {
		// Disabled by default
		active = false

		// Used by Controllers
		loginUrl = '/Shibboleth.sso/Login?target={0}'

		// Token Attributes
		principalUsername.attribute = 'eppn'
		authenticationInstant.attribute = 'Shib-Authentication-Instant'
		username{
			attribute = 'eppn' // sometimes this is 'uid'
			stripAtDomain = false // remove the '@domain.edu' from the username attribute.
		}
		email.attribute = null // sometimes this is 'mail'
		fullName.attribute = null // sometimes this is 'fullName'

		authenticationMethod {
			attribute = 'Shib-Authentication-Method'
			// This maps roles to authentication methods to allow for security annotations
			// for securing based on method
			roles = null
		}

		identityProvider {
			attribute = 'Shib-Identity-Provider'
			// This maps IdPs to authentication methods to allow for security annotations
			// for securing based on originating IdP server
			roles = null
		}
			
		// Used by Authentication Provider
		roles {
			attribute = null
			separator = ','
			prefix = 'SHIB_'
			// Whether or not to load additional roles from another
			// user details service
			loadFromUserDetailsService = false
		}
		extraAttributes = [ 'Shib-Session-Index', 'Shib-Session-ID', 'Shib-AuthnContext-Class', 'Shib-Application-ID' ]

		// Whether to user a shibboleth user details service, or a
		// custom user details service
		useShibbolethUserDetails = true


		login.filterProcessesUrl = "/j_spring_shibboleth_native_sp_security_check"
	}

	// Allow location based roles
	remoteAddress.roles = null

	// change logout URL
	logout.afterLogoutUrl = '/Shibboleth.sso/Logout'
}
