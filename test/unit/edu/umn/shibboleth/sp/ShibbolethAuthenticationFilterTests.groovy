package edu.umn.shibboleth.sp

import static org.junit.Assert.*

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.ProviderManager

import grails.test.mixin.*
import grails.test.mixin.support.*
import org.junit.*

/**
 * See the API for {@link grails.test.mixin.support.GrailsUnitTestMixin} for usage instructions
 */
@TestMixin(GrailsUnitTestMixin)
class ShibbolethAuthenticationFilterTests {

	def detailsServiceSettings
	def filterSettings
	def shibbolethUserDetailsService
	def shibbolethAuthenticationProvider 
	def authenticationManager 

    void setUp() {
        // Setup logic here
		detailsServiceSettings = [
			rolesAttribute: 'Shib-Roles',
			rolesSeparator: ',',
			rolesPrefix: 'SHIBTEST_',
			authenticationMethodRoles: [
				'ROLE_AUTH_METHOD_STANDARD': 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
				'ROLE_AUTH_METHOD_UMN_MKEY': 'https://www.umn.edu/shibboleth/classes/authncontext/mkey' ],
			identityProviderRoles: [
				'ROLE_IDP_UMN': 'https://idp2.shib.umn.edu/idp/shibboleth', 
				'ROLE_IDP_NORTHWESTERN': 'https://fed.it.northwestern.edu/shibboleth-idp/SSO',
				'ROLE_IDP_UMNTEST': 'https://idp-test.shib.umn.edu/idp/shibboleth' ],
			ipAddressRoles: [
				'ROLE_IP_UMN_VPN': ['134.84.0.0/23'], 
				'ROLE_IP_UMN_CAMPUS': ['160.94.0.0/16', '128.101.0.0/16', '134.84.0.0/16'], 
				'ROLE_IP_UMN_DEPT': ['160.94.224.0/25', '128.101.60.128/25', '134.84.107.192/26'] ]
			]

		shibbolethUserDetailsService = new ShibbolethUserDetailsService(detailsServiceSettings)
		shibbolethAuthenticationProvider = new ShibbolethAuthenticationProvider(
			authenticationUserDetailsService: shibbolethUserDetailsService )
		def providers = [ shibbolethAuthenticationProvider ]
		authenticationManager = new ProviderManager(providers: providers)

		filterSettings = [
			principalUsernameAttribute: 'EPPN',
			authenticationMethodAttribute: 'Shib-Authentication-Method',
			identityProviderAttribute: 'Shib-Identity-Provider',
			authenticationInstantAttribute: 'Shib-Authentication-Instant',
			extraAttributes: [ 'Shib-Session-Index', 'Shib-Session-ID', 
				'Shib-AuthnContext-Class', 'Shib-Application-ID' ],
			authenticationManager: authenticationManager
			]

    }

    void testAfterPropertiesSetFail() {

		// EPPN Missing should fail
		shouldFail {
			def shibbolethAuthenticationFilter = new ShibbolethAuthenticationFilter(
				authenticationMethodAttribute: 'Shib-Authentication-Method',
				identityProviderAttribute: 'Shib-Identity-Provider',
				authenticationInstantAttribute: 'Shib-Authentication-Instant',
				extraAttributes: [ 'Shib-AuthnContext-Class', 'Shib-Application-ID' ],
				authenticationManager: authenticationManager)

			shibbolethAuthenticationFilter.afterPropertiesSet()
		}

		// authenticationMethodAttribute missing should fail
		shouldFail {
			def shibbolethAuthenticationFilter = new ShibbolethAuthenticationFilter(
				principalUsernameAttribute: 'EPPN',
				identityProviderAttribute: 'Shib-Identity-Provider',
				authenticationInstantAttribute: 'Shib-Authentication-Instant',
				extraAttributes: [ 'Shib-AuthnContext-Class', 'Shib-Application-ID' ],
				authenticationManager: authenticationManager)

			shibbolethAuthenticationFilter.afterPropertiesSet()
		}

		// identityProviderAttribute missing should fail
		shouldFail {
			def shibbolethAuthenticationFilter = new ShibbolethAuthenticationFilter(
				principalUsernameAttribute: 'EPPN',
				authenticationMethodAttribute: 'Shib-Authentication-Method',
				authenticationInstantAttribute: 'Shib-Authentication-Instant',
				extraAttributes: [ 'Shib-AuthnContext-Class', 'Shib-Application-ID' ],
				authenticationManager: authenticationManager)

			shibbolethAuthenticationFilter.afterPropertiesSet()
		}

		// missing authenticationInstantAttribute should fail
		shouldFail {
			def shibbolethAuthenticationFilter = new ShibbolethAuthenticationFilter(
				principalUsernameAttribute: 'EPPN',
				authenticationMethodAttribute: 'Shib-Authentication-Method',
				identityProviderAttribute: 'Shib-Identity-Provider',
				extraAttributes: [ 'Shib-AuthnContext-Class', 'Shib-Application-ID' ],
				authenticationManager: authenticationManager)

			shibbolethAuthenticationFilter.afterPropertiesSet()
		}

		// missing extraAttributes should fail
		shouldFail {
			def shibbolethAuthenticationFilter = new ShibbolethAuthenticationFilter(
				principalUsernameAttribute: 'EPPN',
				authenticationMethodAttribute: 'Shib-Authentication-Method',
				identityProviderAttribute: 'Shib-Identity-Provider',
				authenticationInstantAttribute: 'Shib-Authentication-Instant',
				authenticationManager: authenticationManager)

			shibbolethAuthenticationFilter.afterPropertiesSet()
		}

		// authenticationManager mission should fail
		shouldFail {
			def shibbolethAuthenticationFilter = new ShibbolethAuthenticationFilter(
				principalUsernameAttribute: 'EPPN',
				authenticationMethodAttribute: 'Shib-Authentication-Method',
				identityProviderAttribute: 'Shib-Identity-Provider',
				authenticationInstantAttribute: 'Shib-Authentication-Instant',
				extraAttributes: [ 'Shib-AuthnContext-Class', 'Shib-Application-ID' ] )

			shibbolethAuthenticationFilter.afterPropertiesSet()
		}
    }

    void testAfterPropertiesSetForDefaults() {

		// Setup the Filter
		def shibbolethAuthenticationFilter = new ShibbolethAuthenticationFilter(filterSettings)

		// make sure everything is setup
		shibbolethAuthenticationFilter.afterPropertiesSet()

		// make sure it worked
		assert shibbolethAuthenticationFilter

    }

    void testFilter() {

		// Setup the Filter
		def shibbolethAuthenticationFilter = new ShibbolethAuthenticationFilter(filterSettings)

		// Mock up Request/Response
		def request = new MockHttpServletRequest('GET', '/')
		def response = new MockHttpServletResponse()

		String username = 'ajz@umn.edu'
		String remoteAddress = '127.0.0.1'
		String identityProvider = 'https://idp-test.shib.umn.edu/idp/'
		String authenticationMethod = 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified'
		String authenticationInstant = '2012-01-16T03:52:19.890Z'

		// add the shibbloleth attributes
		request.setAuthType('shibboleth')
		request.setRemoteUser(username)
		request.setRemoteAddr(remoteAddress)

		request.setAttribute('EPPN', username)
		request.setAttribute('Shib-Application-ID', 'default')
		request.setAttribute('Shib-Authentication-Instant', authenticationInstant)
		request.setAttribute('Shib-Session-Index', 'a927966d65451edf13498352e5bdaaceb8ad108b7656568a1e51cc822bbf5052')
		request.setAttribute('Shib-Authentication-Method', authenticationMethod)
		request.setAttribute('Shib-Identity-Provider', identityProvider)
		request.setAttribute('Shib-AuthnContext-Class', 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified')
		request.setAttribute('Shib-Session-ID', '_dd30caa5aaf4a09ef7335bb1ee1df54b')

		// call authenticate
		def authentication = shibbolethAuthenticationFilter.attemptAuthentication(request, response)

		// make sure it worked
		assert username == authentication.getUsername()
		assert authentication.getPrincipal()

		assertTrue authentication.isAuthenticated()

    }
}
