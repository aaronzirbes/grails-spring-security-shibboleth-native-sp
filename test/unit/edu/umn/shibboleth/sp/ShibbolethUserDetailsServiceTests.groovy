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

	def conf

    void setUp() {
        // Setup logic here
		conf = [
			shibbolethauthenticationMethodattribute: 'Shib-AuthnContext-Method',
			shibbolethidentityProviderattribute: 'Shib-Identity-Provider',
			shibbolethauthenticationInstantattribute: 'Shib-Authentication-Instant',
			shibbolethrolesattribute: null,
			shibbolethrolesseparator: ',',
			shibbolethrolesprefix: 'SHIB_',
			shibbolethextraAttributes: [ 'uid' ],
			shibbolethidentityProviderallowed: null,
			shibbolethauthenticationMethodallowed: null,
			shibbolethauthenticationMethodroles: [
				'ROLE_UMN_MKEY': 'https://www.umn.edu/shibboleth/classes/authncontext/mkey' ],
			remoteAddressroles: [
				'ROLE_UMN_CAMPUS_IP': ['160.94.0.0/16',
					'128.101.0.0/16', 
					'134.84.0.0/16'], 
				'ROLE_ENHS_HS_IP': ['160.94.224.0/25', 
					'128.101.60.128/25', 
					'134.84.107.192/26'] ],
			shibbolethdevelopmentroles: [ 'ROLE_NCS_IT' ],
			shibbolethdevelopmentenvironment: [
				'AUTH_TYPE': 'shibboleth',
				'REMOTE_USER': 'ajz@umn.edu',
				'EPPN': 'ajz@umn.edu',
				'Shib-Application-ID': 'default',
				'Shib-Authentication-Instant': '2011-12-06T21:27:37.423Z',
				'Shib-Session-Index': 'c5ce9e8b65579dcc8f230feded09847f484f3328ea1478fbaab32d14254f7ed4',
				'Shib-Authentication-Method': 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
				'Shib-Identity-Provider': 'https://idp-test.shib.umn.edu/idp/shibboleth',
				'Shib-AuthnContext-Class': 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
				'Shib-Session-ID': '_58872da8c49da55e94bf1c68c7c12745' ]
		]
    }

    void tearDown() {
        // Tear down logic here
    }

    void testUserDetailsInstantiation() {
		def shibbolethUserDetailsService = new ShibbolethUserDetailsService()

		shibbolethUserDetailsService.rolesAttribute = conf.shibbolethrolesattribute
		shibbolethUserDetailsService.rolesSeparator = conf.shibbolethrolesseparator
		shibbolethUserDetailsService.rolesPrefix = conf.shibbolethrolesprefix
		shibbolethUserDetailsService.authenticationMethodRoles = conf.shibbolethauthenticationMethodroles
		shibbolethUserDetailsService.ipAddressRoles = conf.remoteAddressroles
		shibbolethUserDetailsService.developmentRoles = conf.shibbolethdevelopmentroles
    }
}
