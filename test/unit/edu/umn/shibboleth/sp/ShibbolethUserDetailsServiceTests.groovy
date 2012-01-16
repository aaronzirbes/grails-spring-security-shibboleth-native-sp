package edu.umn.shibboleth.sp

import static org.junit.Assert.*

import grails.test.mixin.*
import grails.test.mixin.support.*
import org.junit.*

/**
 * See the API for {@link grails.test.mixin.support.GrailsUnitTestMixin} for usage instructions
 */
@TestMixin(GrailsUnitTestMixin)
class ShibbolethUserDetailsServiceTests {

	def shibbolethToken 
	def detailsServiceSettings

    void setUp() {
        // Setup logic here
		detailsServiceSettings = [
			rolesAttribute: 'Shib-Roles',
			rolesSeparator: ',',
			rolesPrefix: 'SHIBTEST_',
			authenticationMethodRoles: [
				'ROLE_AUTH_METHOD_FAKE': 'fake.authentication.method',
				'ROLE_AUTH_METHOD_STANDARD': 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
				'ROLE_AUTH_METHOD_UMN_MKEY': 'https://www.umn.edu/shibboleth/classes/authncontext/mkey' ],
			identityProviderRoles: [
				'ROLE_IDP_UMN': 'https://idp2.shib.umn.edu/idp/shibboleth', 
				'ROLE_IDP_TEST': 'fake.IdP',
				'ROLE_IDP_NORTHWESTERN': 'https://fed.it.northwestern.edu/shibboleth-idp/SSO',
				'ROLE_IDP_UMNTEST': 'https://idp-test.shib.umn.edu/idp/shibboleth' ],
			ipAddressRoles: [
				'ROLE_IP_UMN_VPN': ['134.84.0.0/23'], 
				'ROLE_IP_LOCALHOST': ['127.0.0.0/24'],
				'ROLE_IP_UMN_CAMPUS': ['160.94.0.0/16', '128.101.0.0/16', '134.84.0.0/16'], 
				'ROLE_IP_UMN_DEPT': ['160.94.224.0/25', '128.101.60.128/25', '134.84.107.192/26'] ]
			]
		
		def authenticationMethod = 'fake.authentication.method'
		def identityProvider = 'fake.IdP'
		def authenticationInstant = '1234567890'
		def authenticationType = 'shibboleth'
		def remoteAddress = '127.0.0.1' 
		def attributes = [ 'someattribute': 'some value' ]
		def eppn = 'me@example.org'

		shibbolethToken = new ShibbolethAuthenticationToken(
			eppn, authenticationType, authenticationMethod, 
			identityProvider, authenticationInstant, 
			remoteAddress, attributes)
    }

    void testUserDetails() {

		def shibbolethUserDetailsService = new ShibbolethUserDetailsService(detailsServiceSettings)

		def userDetails = shibbolethUserDetailsService.loadUserDetails(shibbolethToken)

		assert "me@example.org" == userDetails.username
		assert "some value" == userDetails.attributes['someattribute']
    }

    void testUserDetailsIdpRoles() {

		def shibbolethUserDetailsService = new ShibbolethUserDetailsService(detailsServiceSettings)

		def userDetails = shibbolethUserDetailsService.loadUserDetails(shibbolethToken)

		assertTrue userDetails.authorities.collect{ it.toString() }.contains('ROLE_IDP_TEST')
		assertFalse userDetails.authorities.collect{ it.toString() }.contains('ROLE_IDP_UMN')
		assertFalse userDetails.authorities.collect{ it.toString() }.contains('ROLE_IDP_NORTHWESTERN')
    }

    void testUserDetailsMethodRoles() {

		def shibbolethUserDetailsService = new ShibbolethUserDetailsService(detailsServiceSettings)

		def userDetails = shibbolethUserDetailsService.loadUserDetails(shibbolethToken)

		assertTrue userDetails.authorities.collect{ it.toString() }.contains('ROLE_AUTH_METHOD_FAKE')
		assertFalse userDetails.authorities.collect{ it.toString() }.contains('ROLE_AUTH_METHOD_STANDARD')
		assertFalse userDetails.authorities.collect{ it.toString() }.contains('ROLE_AUTH_METHOD_UMN_MKEY')
    }

    void testUserDetailsIpRoles() {

		def shibbolethUserDetailsService = new ShibbolethUserDetailsService(detailsServiceSettings)

		def userDetails = shibbolethUserDetailsService.loadUserDetails(shibbolethToken)

		assertTrue userDetails.authorities.collect{ it.toString() }.contains('ROLE_IP_LOCALHOST')
		assertFalse userDetails.authorities.collect{ it.toString() }.contains('ROLE_IP_UMN_CAMPUS')
		assertFalse userDetails.authorities.collect{ it.toString() }.contains('ROLE_IP_UMN_VPN')
    }
}

