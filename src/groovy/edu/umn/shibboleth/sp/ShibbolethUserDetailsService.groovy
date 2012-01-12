package edu.umn.shibboleth.sp

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.util.IpAddressMatcher

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
	private static final String DEFAULT_PRINCIPAL_USERNAME_ATTRIBUTE = "eppn"
	private static final String DEFAULT_ROLES_ATTRIBUTE = null
	private static final String DEFAULT_ROLES_SEPARATOR = "W,"
	private static final String DEFAULT_ROLES_PREFIX = "SHIB_"

	/** This is the exposed attribute that contains the user's roles */
	String rolesAttribute = DEFAULT_ROLES_ATTRIBUTE
	/** This is the delimiter for the roles attribute value */
	String rolesSeparator = DEFAULT_ROLES_SEPARATOR
	/** This is the prefix to apply to all the roles loaded from the exposed roles attribute */
	String rolesPrefix = DEFAULT_ROLES_PREFIX
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
	 * This is to support the {@code RememberMeService}
	 */
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// Look up the user via RememberMeService
		UserDetails user = registeredUsers.get(id)

		// If the user isn't found, throw an exception
		if (user == null) { throw new UsernameNotFoundException(id) }

		// else return the remembered UserDetails
		return user
	}

	/**
	 * This loads the user details from the shibboleth attributes passed in the
	 * {@code ShibbolethAuthenticationToken}
	 */
	UserDetails loadUserDetails(Authentication authentication) throws UsernameNotFoundException {

		log.debug("ShibbolethUserDetailsService.loadUserDetails():: invocation")

		// set default values
		def username = authentication.name
		def password = ''
		def enabled = true
		def accountNonExpired = true
		def credentialsNonExpired = true
		def accountNonLocked = true
		def eppn = authentication.eppn
		def attributes = authorities.attributes

		Collection<GrantedAuthorityImpl> authorities
		Collection<GrantedAuthorityImpl> ipAuthorities
		Collection<GrantedAuthorityImpl> shibbolethAuthorities

		// Load IP based roles if enabled
		if (ipAddressRoles) {
			ipAddressRoles.each{ role, ipList ->
				ipList.each{ ip ->
					if (new IpAddressMatcher(ip).matches(remoteAddress)) {
						ipAuthorities.add(new GrantedAuthorityImpl(role))
					}
				}
			}
			if (ipAuthorities) { 
				authorities.addAll(ipAuthorities)
			}
		}

		// Load Shibboleth roles if enabled
		if (rolesAttribute && rolesSeparator && rolesPrefix) {
			def rolesString =  authentication.attributes[rolesAttribute]
			def rolesCollection = rolesString.split(rolesSeparator)
			shibbolethAuthorities = rolesCollection.collect{
				new GrantedAuthorityImpl( 'ROLE_' + rolesPrefix + it.toUpperCase() ) 
			}

			// add the new shibboleth authorities to the authorities attribute
			authorities.addAll(shibbolethAuthorities)
		}

		// if identityProvider based roles are defined, assign them here
		if (identityProviderRoles) {
			identityProviderRoles.each{ roleName, provider ->
				// if the authentication method matches the method used,
				// then add the corresponding role to the authorities
				if (provider == authentication.identityProvider) {
					authorities.add(new GrantedAuthorityImpl(roleName))
				}
			}
		}

		// if authenticationMethod based roles are defined, assign them here
		if (authenticationMethodRoles) {
			authenticationMethodRoles.each{ roleName, method ->
				// if the authentication method matches the method used,
				// then add the corresponding role to the authorities
				if (method == authentication.authenticationMethod) {
					authorities.add(new GrantedAuthorityImpl(roleName))
				}
			}
		}

		// If no authorities were set, set the default
		if (! authorities) { authorities = DEFAULT_AUTHORITIES }

		// return new ShibbolethUser (principal)
		return new ShibbolethUserDetails(username, password, enabled, accountNonExpired,
			credentialsNonExpired, accountNonLocked, authorities, eppn, attributes)

	}
}
