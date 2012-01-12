package edu.umn.shibboleth.sp;

import java.util.Collection;
import java.util.List;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.util.IpAddressMatcher;
import org.springframework.util.Assert;

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

	//~ Instance fields ===================================================================================
	
	// Support for Shibboleth User Details Service
	private AuthenticationUserDetailsService authenticationUserDetailsService;
	// TODO: Support DAO Details Service if configured
	// TODO: Support LDAP Details Service if plugin installed and configured
	// TODO: Support Active Directory Details Service if configured

	//~ Methods ===========================================================================================

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(authenticationUserDetailsService, "An authenticationUserDetailsService must be set");
	}

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

		if (shibToken.getAuthenticationType() == null) {
			throw new BadCredentialsException("authenticationType is null");
		} else if (shibToken.getAuthenticationType().length() == 0) {
			throw new BadCredentialsException("authenticationType is empty");
		} else if ( ! shibToken.getAuthenticationType().equals("shibboleth") ) {
			throw new BadCredentialsException("authenticationType, '" + shibToken.getAuthenticationType() + "' != 'shibboleth'");
		} else if (shibToken.getEppn() == null) {
			throw new BadCredentialsException("eppn is null");
		} else if (shibToken.getEppn().length() == 0) {
			throw new BadCredentialsException("eppn is empty");
		} else if (shibToken.getIdentityProvider() == null) {
			throw new BadCredentialsException("identityProvider is null");
		} else if (shibToken.getIdentityProvider().length() == 0) {
			throw new BadCredentialsException("identityProvider is empty");
		} else if (shibToken.getAuthenticationInstant() == null) {
			throw new BadCredentialsException("authenticationInstant is null");
		} else if (shibToken.getAuthenticationInstant().length() == 0) {
			throw new BadCredentialsException("authenticationInstant is empty");
		} else if (shibToken.getAuthenticationMethod() == null) {
			throw new BadCredentialsException("authenticationMethod is null");
		} else if (shibToken.getAuthenticationMethod().length() == 0) {
			throw new BadCredentialsException("authenticationMethod is empty");
		} else {
			authenticationValid = true;
		}

		// Return new authentication object if authenticated
		if (authenticationValid) {

			// set default principal and authorities
			Object principal = shibToken.getEppn();
			Collection<GrantedAuthority> authorities = shibToken.getAuthorities();

			// load user details from the authentication
			UserDetails userDetails = this.authenticationUserDetailsService.loadUserDetails(shibToken);
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

	/** Returns true if the Authentication implementation passed is supported
	 * by the {@code ShibbolethAuthenticationProvider#authenticate} method.
	 */
	public boolean supports(Class<? extends Object> authentication) {
		return ShibbolethAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Used to load the authorities and user details for the Shibboleth service
	 */
	public void setUserDetailsService(final UserDetailsService userDetailsService) {
		this.authenticationUserDetailsService = new UserDetailsByNameServiceWrapper(userDetailsService);
	}

	/**
	 * Used to load the authorities and user details for the Shibboleth service
	 */
	public void setAuthenticationUserDetailsService(final AuthenticationUserDetailsService authenticationUserDetailsService) {
		this.authenticationUserDetailsService = authenticationUserDetailsService;
	}
}
