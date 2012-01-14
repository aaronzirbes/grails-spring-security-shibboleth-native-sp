security {
	shibboleth {
		// Disabled by default
		active = false

		// Used by Controllers
		loginUrl = '/Shibboleth.sso/Login?target={0}'

		// Token Attributes
		principalUsername.attribute = 'EPPN'
		authenticationMethod.attribute = 'Shib-Authentication-Method'
		identityProvider.attribute = 'Shib-Identity-Provider'
		authenticationInstant.attribute = 'Shib-Authentication-Instant'
			
		// Used by Authentication Provider
		roles.attribute = null
		roles.separator = ','
		roles.prefix = 'SHIB_'
		extraAttributes = [ 'Shib-Session-Index', 'Shib-Session-ID', 'Shib-AuthnContext-Class', 'Shib-Application-ID' ]

		// This maps IdPs to authentication methods to allow for security annotations
		// for securing based on originating IdP server
		identityProvider.roles = null

		// This maps roles to authentication methods to allow for security annotations
		// for securing based on method
		authenticationMethod.roles = null
	}

	// Allow location based roles
	remoteAddress.roles = null

	// change logout URL
	logout.afterLogoutUrl = '/Shibboleth.sso/Logout'
}
