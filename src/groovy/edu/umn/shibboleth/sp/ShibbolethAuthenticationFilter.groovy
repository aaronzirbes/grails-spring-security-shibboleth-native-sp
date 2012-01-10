package edu.umn.shibboleth.sp

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.apache.log4j.Logger
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter


/**
	Processes a {@link ShibbolethAuthenticationToken}, and authenticates via Shibboleth if available.

	@author <a href="mailto:ajz@umn.edu">Aaron J. Zirbes</a>
*/
class ShibbolethAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private static final log = Logger.getLogger(this)

	// configuration settings + default values
	// def principalUsernameAttribute = 'EPPN'
	String principalUsernameAttribute = null
	String authenticationMethodAttribute = 'Shib-AuthnContext-Method'
	String identityProviderAttribute = 'Shib-Identity-Provider'
	String authenticationInstantAttribute = 'Shib-Authentication-Instant'
	Map<String,String> developmentEnvironment = new HashMap<String, String>()
	Collection<String> extraAttributes = new ArrayList<String>()

	/** The default constructor */
	public ShibbolethAuthenticationFilter() {
		super("/j_spring_shibboleth_native_sp_security_check")
		log.debug "instantiation"
	}

	/** Try logging in the user via Shibboleth Native SP */
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {

		Authentication token = null
		ShibbolethAuthenticationToken shibbolethAuthenticationToken = null

		log.debug "attemptAuthentication():: invocation"

		// These are set by mod_shib22 in Apache and passed through mod_jk 
		// to the servlet (Tomcat, Glassfish, etc..)
		// This means you MUST trust the assertions chain made by mod_jk, and in 
		// turn Apache, and in turn mod_shib22, and in turn the Shibboleth SP (shibd)
		// This is often referred to as "pre-authentication"
		def remoteUser = request.getRemoteUser()
		def remoteAddress = request.getRemoteAddress()
		def authType = request.getAuthType()

		// These are configurable attributes to load
		def authenticationMethod = request.getAttribute(authenticationMethodAttribute)
		def identityProvider = request.getAttribute(identityProviderAttribute)
		def authenticationInstant = request.getAttribute(authenticationInstantAttribute)
		// overwrite the remoteUser if the principalUsernameAttribute was set, and contains a value
		remoteUser = request.getAttribute(principalUsernameAttribute) ?: remoteUser

		def attributes = [:]

		// load any extra attributes
		extraAttributes.each{
			attributes[it] = request.getAttribute(it)?.toString()
		}

		// This is used to make development easier to allow overwriting attributes
		if (developmentEnvironment) {
			log.debug "attemptAuthentication():: loading debug environment"

			authType				= developmentEnvironment['AUTH_TYPE'] ?: authType
			authenticationMethod	= developmentEnvironment[authenticationMethodAttribute] ?: authenticationMethod
			identityProvider		= developmentEnvironment[identityProviderAttribute] ?: identityProvider
			authenticationInstant	= developmentEnvironment[authenticationInstantAttribute] ?: authenticationInstant
			remoteUser				= developmentEnvironment[principalUsernameAttribute] ?: remoteUser

			// load any defined 'extraAttributes' exposed by the IdP
			extraAttributes.each{
				attributes[it] = developmentEnvironment[it] ?: attributes[it]
			}
		}
		
		// INFO: authType is not configurable, as this plugin 
		// is meant to be used with the Shibboleth Native SP that 
		// integrates with Apache
		if ( remoteUser && authType && authType == 'shibboleth' ) {
			// create the token
			// principal is set to remoteUser because the default string convert (toString)
			// for the AbstractAuthenticationProcessingFilter class is principal.toString()

			log.debug "attemptAuthentication():: building a shibboleth token"

			shibbolethAuthenticationToken = new ShibbolethAuthenticationToken(
				remoteUser, null, eppn, null, remoteUser, false, remoteUser,
				authType, authenticationMethod, identityProvider, authenticationInstant,
				remoteAddress, attributes)

			log.debug "attemptAuthentication():: calling authenticate"
			token = authenticationManager.authenticate(shibbolethAuthenticationToken)
		}

		return token
	}
}
