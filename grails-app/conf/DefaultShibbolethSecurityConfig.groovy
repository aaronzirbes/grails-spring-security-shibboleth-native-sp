security {
	shibboleth {
		// Disabled by default
		active = false

		// Used by Controllers
		loginUrl = '/Shibboleth.sso/Login?target={0}'
		logoutUrl = '/Shibboleth.sso/Logout'

		// Token Attributes
		principalUsername.attribute = 'EPPN'
		authenticationMethod.attribute = 'Shib-AuthnContext-Method'
		identityProvider.attribute = 'Shib-Identity-Provider'
		authenticationInstant.attribute = 'Shib-Authentication-Instant'
			
		// Used by Authentication Provider
		roles.attribute = null
		roles.separator = ','
		roles.prefix = 'SHIB_'
		extraAttributes = [ 'Shib-Session-Index', 'Shib-Session-ID', 'Shib-AuthnContext-Class', 'Shib-Application-ID' ]

		identityProvider.allowed = null
		// identityProvider.allowed = [ 'https://idp-test.shib.umn.edu/idp/shibboleth' ]
		// identityProvider.allowed = [ 'https://idp2.shib.umn.edu/idp/shibboleth', 'https://idp-test.shib.umn.edu/idp/shibboleth' ]

		authenticationMethod.allowed = null
		// authenticationMethod.allowed = [ 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified' ]
		// authenticationMethod.allowed = [ 'https://www.umn.edu/shibboleth/classes/authncontext/mkey' ]

		// This maps roles to authentication methods to allow for security annotations
		// for securing based on method
		authenticationMethod.roles = null

		// authenticationMethod.roles = null

		// Allow location based roles
		grails.plugins.springsecurity.remoteaddress.roles = null

		// grails.plugins.springsecurity.ipRoles = null

		// The following settings can be used for simulating a shibboleth environment
		// when running in development mode

		// Used to create a development roles for the test environment
		development.roles = null

		// Used to create a development envirornment for shibboleth secured applications
		development.environment = null
	}
}
