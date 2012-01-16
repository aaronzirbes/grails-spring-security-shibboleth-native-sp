package edu.umn.shibboleth.sp

import static org.junit.Assert.*

import grails.test.mixin.*
import grails.test.mixin.support.*
import org.junit.*

/**
 * See the API for {@link grails.test.mixin.support.GrailsUnitTestMixin} for usage instructions
 */
@TestMixin(GrailsUnitTestMixin)
class ShibbolethAuthenticationProviderTests {

	def detailsServiceSettings
	ShibbolethUserDetailsService shibbolethUserDetailsService
	ShibbolethAuthenticationToken shibbolethToken

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

		def authenticationMethod = 'fake.authentication.method'
		def identityProvider = 'fake.IdP'
		def authenticationInstant = '1234567890'
		def authenticationType = 'shibboleth'
		def remoteAddress = '127.0.0.1' 
		def attributes = [:]
		def eppn = 'me@example.org'

		shibbolethToken = new ShibbolethAuthenticationToken(
			eppn, authenticationType, authenticationMethod, 
			identityProvider, authenticationInstant, 
			remoteAddress, attributes)

    }

	void testShibbolethTokenOk() {
		String username = 'me@example.org'
		assert username == shibbolethToken.username
	}

	void testAfterPropertiesSet() {
		def shibbolethAuthenticationProvider = new ShibbolethAuthenticationProvider()

		shouldFail{
			shibbolethAuthenticationProvider.afterPropertiesSet()
		}
	}

    void testSupportsShibToken() {

		def shibbolethAuthenticationProvider = new ShibbolethAuthenticationProvider(
			authenticationUserDetailsService: shibbolethUserDetailsService)

		boolean supported = shibbolethAuthenticationProvider.supports(shibbolethToken.getClass())

		assertTrue supported
    }

    void testAuthenticatedShibbolethToken() {

		def shibbolethAuthenticationProvider = new ShibbolethAuthenticationProvider(
			authenticationUserDetailsService: shibbolethUserDetailsService)

		def newToken = shibbolethAuthenticationProvider.authenticate(shibbolethToken)

		assert shibbolethToken.username == newToken.username
		assert false == shibbolethToken.isAuthenticated()
		assert true == newToken.isAuthenticated()

    }
}
