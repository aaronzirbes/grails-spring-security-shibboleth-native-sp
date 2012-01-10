package edu.umn.shibboleth.sp;

import java.util.Collection;
import java.util.List;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.util.IpAddressMatcher;
import org.springframework.util.Assert;
import org.apache.log4j.Logger;

/**
 * An {@link AuthenticationProvider} implementation that integrates
 * with the native Shibboleth SP (Service Provider).
 * 
 * This <code>AuthenticationProvider</code> is capable of validating
 * {@link ShibbolethAuthenticationToken} requests which contain an
 * eppn name equal to HttpServletRequest.remoteUser
 * 
 * @author <a href="mailto:ajz@umn.edu">Aaron J. Zirbes</a>
 */
class ShibbolethAuthenticationProvider implements AuthenticationProvider, InitializingBean {

	private final Logger logger = Logger.getLogger(this.getClass());

	// injected service(s)
	private ShibbolethUserDetailsService userDetailsService = null;

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
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		logger.debug("authenticate():: invocation");

		// exit if unsupported token is passed
		if (!supports(authentication.getClass())) {
			return null;
		}

		boolean authenticationValid = false;

		// cast token to a ShibbolethAuthenticationToken
		ShibbolethAuthenticationToken shibToken = (ShibbolethAuthenticationToken) authentication;

		
		// mark the authentication as valid if all the required Shib elements are present
		if (shibToken.getAuthenticationType().equals("shibboleth")
				&& shibToken.getEppn().length() > 0
				&& shibToken.getIdentityProvider().length() > 0
				&& shibToken.getAuthenticationInstant().length() > 0
				&& shibToken.getAuthenticationMethod().length() > 0) {
			authenticationValid = true;
		} else {
			throw new BadCredentialsException("required shibboleth attributes are missing.");
		}

		// if a restricted list of allowed identityProviders (IdP) is defined,
		// make sure that the identityProvider used is in the whitelist
		if (identityProviderAllowed.size() > 0) {
			// if the white list does NOT contain the IdP used...
			if ( ! identityProviderAllowed.contains(shibToken.getIdentityProvider()) ) {
				// ...mark this as invalid.
				authenticationValid = false;
				throw new BadCredentialsException("identity provider: " + shibToken.getIdentityProvider() + ", not allowed");
			}
		}
		
		// if a restricted list of allowed authentication methods is configured,
		// make sure that the authenticationMethod used is in the whitelist
		if (authenticationMethodAllowed.size() > 0) {
			// if the white list does NOT contain the method used...
			if ( ! authenticationMethodAllowed.contains(shibToken.getAuthenticationMethod()) ) {
				// ...mark this as invalid.
				authenticationValid = false;
				throw new BadCredentialsException("authentication method: " + shibToken.getAuthenticationMethod() + ", not allowed");
			}
		}

		// Return new authentication object if authenticated
		if (authenticationValid) {

			// set default principal and authorities
			Object principal = shibToken.getEppn();
			Collection<GrantedAuthority> authorities = shibToken.getAuthorities();

			// load user details from the authentication
			UserDetails userDetails = userDetailsService.loadUserDetails(shibToken);
			if (userDetails != null) {
		   		principal = userDetails;
				authorities = userDetails.getAuthorities();
			} else {
		   		principal = shibToken.getEppn();
			}

			return new ShibbolethAuthenticationToken(authorities,
					shibToken.getDetails(), principal, shibToken.getEppn(), 
					shibToken.getAuthenticationType(), shibToken.getAuthenticationMethod(),
					shibToken.getIdentityProvider(), shibToken.getAuthenticationInstant(),
					shibToken.getRemoteAddress(), shibToken.getAttributes());

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
	public boolean supports(Class authentication) {
		return ShibbolethAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
