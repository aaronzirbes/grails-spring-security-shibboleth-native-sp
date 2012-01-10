package edu.umn.shibboleth.sp

import org.springframework.beans.factory.InitializingBean
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.web.util.IpAddressMatcher
import org.springframework.util.Assert

/**
	An {@link AuthenticationProvider} implementation that integrates
	with the native Shibboleth SP (Service Provider).

	This <code>AuthenticationProvider</code> is capable of validating
	{@link ShibbolethAuthenticationToken} requests which contain a 
	principal name equal to HttpServletRequest.remoteUser

	@author <a href="mailto:ajz@umn.edu">Aaron J. Zirbes</a>
*/
class ShibbolethAuthenticationProvider implements AuthenticationProvider, InitializingBean {

	// injected service(s)
	Object userDetailsService;

	// configuration settings + default values
	// def principalUsernameAttribute = 'EPPN'
	// injected configuration parameters
	Collection<String> identityProviderAllowed = null;
	Collection<String> authenticationMethodAllowed = null;

	public ShibbolethAuthenticationProvider() {
		super();
		logger.debug("instantiation");
	}

	/** 
	This attempts to authenticate an {@link Authentication} using the native Shibboleth SP
	*/
	Authentication authenticate(Authentication authentication) throws AuthenticationException {

		logger.debug("authenticate():: invocation");

		// exit if unsupported token is passed
		if (!supports(authentication.getClass())) {
			return null;
		}

		boolean authenticationValid = false;
		
		// mark the authentication as valid if all the required Shib elements are present
		if (authentication.authenticationType.equals("shibboleth")
				&& authentication.eppn.length() > 0
				&& authentication.identityProvider.length() > 0
				&& authentication.authenticationInstant.length() > 0
				&& authentication.authenticationMethod.length() > 0) {
			authenticationValid = true;
		} else {
			throw new BadCredentialsException("required shibboleth attributes are missing.")
		}

		// if a restricted list of allowed identityProviders (IdP) is defined,
		// make sure that the identityProvider used is in the whitelist
		if (identityProviderAllowed.size() > 0) {
			// if the white list does NOT contain the IdP used...
			if ( ! identityProviderAllowed.contains(authentication.identityProvider) ) {
				// ...mark this as invalid.
				authenticationValid = false;
				throw new BadCredentialsException("identity provider: " + authentication.identityProvider + ", not allowed");
			}
		}
		
		// if a restricted list of allowed authentication methods is configured,
		// make sure that the authenticationMethod used is in the whitelist
		if (authenticationMethodAllowed.size() > 0) {
			// if the white list does NOT contain the method used...
			if ( ! authenticationMethodAllowed.contains(authentication.authenticationMethod) ) {
				// ...mark this as invalid.
				authenticationValid = false;
				throw new BadCredentialsException("authentication method: " + authentication.authenticationMethod + ", not allowed");
			}
		}

		// Return new authentication object if authenticated
		if (authenticationValid) {

			// cast token to a ShibbolethAuthenticationToken
			ShibbolethAuthenticationToken shibToken = (ShibbolethAuthenticationToken) authentication;

			// load user details from the authentication
			UserDetails userDetails = userDetailsService.loadUserDetails(shibToken)
			if (userDetails != null) {
		   		userDetails = authentication.eppn;
			}

			return new ShibbolethAuthenticationToken(userDetails.authorities,
					authentication.details, userDetails, authentication.eppn, 
					authentication.authenticationType, authentication.authenticationMethod,
					authentication.identityProvider, authentication.authenticationInstant,
					authentication.remoteAddress, authentication.attributes);

		} else {
			return null;
		}
	}

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(userDetailsService, "userDetailsService must be set");
	}

	/** Returns true if the Authentication implementation passed is supported
	 * by the {@code ShibbolethAuthenticationProvider#authenticate} method.
	 */
	boolean supports(Class authentication) {
		return ShibbolethAuthenticationToken.class.isAssignableFrom(authentication);
	}
}

