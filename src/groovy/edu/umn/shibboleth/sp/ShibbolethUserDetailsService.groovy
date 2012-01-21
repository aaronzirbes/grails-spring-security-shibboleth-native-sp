package edu.umn.shibboleth.sp

import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.util.IpAddressMatcher
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator

/**
	Abstract class for using the provided Shibboleth assertion to construct
	a new {@link ShibbolethUser} object.  This generally is most useful when
	combined with additional exposed attributes returned to the Shibboleth
	native SP from the IdP.
	<p/>
	Reference Documentation
	<ul>
	<li><a href="http://static.springsource.org/spring-security/site/reference.html">Spring Security Documentation</a></li>
	<li><a href="http://grails-plugins.github.com/grails-spring-security-core/">Grails Spring Security Core Documentation</a></li>
	</ul>

	@author <a href="mailto:ajz@umn.edu">Aaron J. Zirbes</a>
*/
class ShibbolethUserDetailsService implements UserDetailsService, AuthenticationUserDetailsService {

	/**
	 * This is to support the {@code RememberMeService}
	 */
	private final Map<String, ShibbolethUserDetails> registeredUsers = new HashMap<String, ShibbolethUserDetails>()
	/**
	 * Some Spring Security classes (e.g. RoleHierarchyVoter) expect at least one role, so
	 * we give a user with no granted roles this one which gets past that restriction but
	 * doesn't grant anything.
	 */
	private static final List<GrantedAuthority> DEFAULT_AUTHORITIES = AuthorityUtils.createAuthorityList("ROLE_USER")
	private static final String DEFAULT_ROLES_ATTRIBUTE = null
	private static final String DEFAULT_ROLES_SEPARATOR = "W,"
	private static final String DEFAULT_ROLES_PREFIX = "SHIB_"
	private static final String DEFAULT_EMAIL_ATTRIBUTE = null
	private static final String DEFAULT_FULLNAME_ATTRIBUTE = null

	/** This is the exposed attribute that contains the user's roles */
	String rolesAttribute = DEFAULT_ROLES_ATTRIBUTE
	/** This is the delimiter for the roles attribute value */
	String rolesSeparator = DEFAULT_ROLES_SEPARATOR
	/** This is the prefix to apply to all the roles loaded from the exposed roles attribute */
	String rolesPrefix = DEFAULT_ROLES_PREFIX
	/** This is the optional attribute that contains the user's full name */
	String emailAttribute = DEFAULT_EMAIL_ATTRIBUTE
	/** This is the optional attribute that contains the user's email address */
	String fullNameAttribute = DEFAULT_FULLNAME_ATTRIBUTE
	/** This is a map of roles to apply when specific authentication methods are used.
	  * This is primarily used to identify guest or two-factor authentication. */
	HashMap<String, String> authenticationMethodRoles = new HashMap<String, String>()
	/** 
	 * This is a collection of map objects that contain a role, and an associated
	 * identity provider.
	 * This can be used to identify the IdP that authenticated the logged in user. */
	HashMap<String, String> identityProviderRoles = new HashMap<String, String>()
	/** 
	 * This is a collection of map objects that contain a role, and an associated
	 * collection of remote ip address ranges that cause the role to be applied.
	 * This can be used to identify when two-factor authentication is needed based on
	 * the clients network.
	 * This configuration attribute is why this is still a Groovy class */
	def ipAddressRoles = null

	/**
	 * This is to support loading roles from LDAP
	 */
	String userDnBase
	DefaultLdapAuthoritiesPopulator ldapAuthoritiesPopulator

	/**
	 * This is to support loading roles from any userDetailsService, this includes
	 * but is not limited to the DAO user details service that can load roles
	 * from GORM.
	 */
	UserDetailsService userDetailsService

	/**
	 * This is to support the {@code RememberMeService}
	 */
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// Look up the user via RememberMeService
		UserDetails user = registeredUsers.get(username)

		// If the user isn't found, throw an exception
		if (user == null) { throw new UsernameNotFoundException(username) }

		// else return the remembered UserDetails
		return user
	}

	/**
	 * This loads the user details from the shibboleth attributes passed in the
	 * {@code ShibbolethAuthenticationToken}
	 */
	public UserDetails loadUserDetails(Authentication authentication) {

		ShibbolethAuthenticationToken shibAuthToken

		// Try to convert the authentication to a ShibbolethAuthenticationToken
		try {
			shibAuthToken = (ShibbolethAuthenticationToken) authentication
		} catch (ClassCastException ex) {
			logger.trace(ex)
			throw new BadCredentialsException('you must provide a ShibbolethAuthenticationToken')
		}
		// Exit if the conversion was unsuccessful
		if (! shibAuthToken) { return false }


		// set default values
		String username = shibAuthToken.name
		String fullName = null
		String email = null
		String eppn = shibAuthToken.eppn
		Map<String, String> attributes = shibAuthToken.attributes

		def newAuthorities = [] as Set

		// Load Shibboleth roles if enabled
		if (rolesAttribute && rolesSeparator && rolesPrefix && shibAuthToken.attributes.containsKey(rolesAttribute)) {
			String rolesString =  shibAuthToken.attributes[rolesAttribute]
			if (rolesString) {
				Collection<String> rolesCollection = new ArrayList<String>()
				rolesCollection.addAll( rolesString.split(rolesSeparator) )
				rolesCollection.each{
					def role = new GrantedAuthorityImpl( 'ROLE_' + rolesPrefix + it.toUpperCase() ) 
					newAuthorities.add(role)
				}
			}
		}

		// Get fullname if available
		if (fullNameAttribute && shibAuthToken.attributes.containsKey(fullNameAttribute)) {
			fullName = shibAuthToken.attributes[fullNameAttribute]
		}

		// Get email if available
		if (emailAttribute && shibAuthToken.attributes.containsKey(emailAttribute)) {
			email = shibAuthToken.attributes[emailAttribute]
		}

		// Load IP based roles if enabled
		if (ipAddressRoles) {
			ipAddressRoles.each{ role, ipList ->
				ipList.each{ ip ->
					if (new IpAddressMatcher(ip).matches(shibAuthToken.remoteAddress)) {
						def auth = new GrantedAuthorityImpl(role)
						newAuthorities.add(auth)
					}
				}
			}
		}

		// if identityProvider based roles are defined, assign them here
		if (identityProviderRoles) {
			identityProviderRoles.each{ roleName, provider ->
				// if the authentication method matches the method used,
				// then add the corresponding role to the newAuthorities
				if (provider == shibAuthToken.identityProvider) {
					newAuthorities.add(new GrantedAuthorityImpl(roleName))
				}
			}
		}

		// if authenticationMethod based roles are defined, assign them here
		if (authenticationMethodRoles) {
			authenticationMethodRoles.each{ roleName, method ->
				// if the authentication method matches the method used,
				// then add the corresponding role to the newAuthorities
				if (method == shibAuthToken.authenticationMethod) {
					newAuthorities.add(new GrantedAuthorityImpl(roleName))
				}
			}
		}

		// if LDAP is configured and enabled, load LDAP roles
		if (userDnBase && ldapAuthoritiesPopulator) {
			// TODO: replace this userDn contstructor with the LDAP user search.  It works for me though for now...
			String userDn = 'cn=' + username + ',' + userDnBase
			def ldapAuthorities = ldapAuthoritiesPopulator.getGroupMembershipRoles(userDn, username)

			ldapAuthorities.each{ role ->
				// Add the LDAP roles
				newAuthorities.add(new GrantedAuthorityImpl(role.getAuthority().toString()))
			}
		}

		// if userDetailsService is set, try to load roles from there too!
		if (userDetailsService) {
			UserDetails userDetails = userDetailsService.loadUserByUsername(username)
			userDetails?.authorities.each{ role ->
				newAuthorities.add(new GrantedAuthorityImpl(role.getAuthority().toString()))
			}
		}

		// If no newAuthorities were set, set the default
		if (! newAuthorities) { newAuthorities = DEFAULT_AUTHORITIES }

		// return new ShibbolethUser (principal)
		return new ShibbolethUserDetails(username, email, 
			fullName, newAuthorities, eppn, attributes)

	}
}
