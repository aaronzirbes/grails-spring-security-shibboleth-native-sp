package edu.umn.shibboleth.sp

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.authentication.AbstractAuthenticationToken

/**
	An {@link Authentication} object needed to load the {@link ShibbolethUserDetailsService}
	with the native Shibboleth SP (Service Provider).

	This <code>ShibbolethAuthenticationToken</code> is capable of loading an {@link Authentication}
	from an eppn provided by the shibboleth native SP.

	@author <a href="mailto:ajz@umn.edu">Aaron J. Zirbes</a>
*/
class ShibbolethAuthenticationToken extends AbstractAuthenticationToken implements Serializable {

	private String name
	private Object credentials
	private Object details
	private Object principal
	private boolean authenticated

	// Extra token attributes for Shibboleth
	// These are all things that need to be pulled in from the
	// request object for processing by the ShibbolethUserDetailsService
	private String eppn
	private String authenticationType
	private String authenticationMethod
	private String identityProvider
	private String authenticationInstant
	private String remoteAddress
	private Map<String, String> attributes

	public ShibbolethAuthenticationToken(String name, Collection<GrantedAuthority> authorities, 
			Object credentials, Object details, Object principal, boolean authenticated, 
			String eppn, String authenticationType, String authenticationMethod, 
			String identityProvider, String authenticationInstant, 
			String remoteAddress, Map<String, String> attributes) {

		super(authorities)

		this.name = name 
		this.credentials = credentials
		this.details = details
		this.principal = principal
		this.authenticated = authenticated
		this.eppn = eppn
		this.authenticationType = authenticationType
		this.authenticationMethod = authenticationMethod
		this.identityProvider = identityProvider
		this.authenticationInstant = authenticationInstant
		this.remoteAddress = remoteAddress
		this.attributes = attributes
	}

	/** Getter for name */
	String getName() {
		name
	}

	/** Getter for credentials */
	Object getCredentials() {
		credentials
	}

	/** Getter for details */
	Object getDetails() {
		details
	}

	/** Getter for principal */
	Object getPrincipal() {
		principal
	}

	/** Getter for authenticated */
	boolean getAuthenticated() {
		authenticated
	}

	/** Getter for eppn */
	String getEppn() {
		eppn
	}

	/** Getter for authenticationType */
	String getAuthenticationType() {
		authenticationType
	}

	/** Getter for authenticationMethod */
	String getAuthenticationMethod() {
		authenticationMethod
	}

	/** Getter for identityProvider */
	String getIdentityProvider() {
		identityProvider
	}

	/** Getter for authenticationInstant */
	String getAuthenticationInstant() {
		authenticationInstant
	}

	/** Getter for remoteAddress */
	String getRemoteAddress() {
		remoteAddress
	}

	/** Getter for attributes */
	Map<String, String> getAttributes() {
		attributes
	}
}
