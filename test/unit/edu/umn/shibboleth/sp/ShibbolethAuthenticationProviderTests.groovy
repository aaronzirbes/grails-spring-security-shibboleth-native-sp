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

    void setUp() {
        // Setup logic here
    }

    void tearDown() {
        // Tear down logic here
    }

    void testSupportsShibToken() {
		def shibbolethAuthenticationProvider = new ShibbolethAuthenticationProvider()

		def authenticationMethod = 'fake.authentication.method'
		def identityProvider = 'fake.IdP'
		def authenticationInstant = '1234567890'
		def authenticationType = 'something'
		def remoteAddress = '127.0.0.1' 
		def attributes = [:]
		def name = 'me@example.org'
		def eppn = 'me@example.org'
		def credentials = 'shibboleth'
		def principal = 'me@example.org'
		def authenticated = true
		def authorities = []
		def details = null

		def shibbolethAuthenticationToken = new ShibbolethAuthenticationToken(name, 
			authorities, credentials, details, principal, authenticated, 
			eppn, authenticationType, authenticationMethod, 
			identityProvider, authenticationInstant, 
			remoteAddress, attributes)

		assertTrue shibbolethAuthenticationProvider.supports(shibbolethAuthenticationToken.getClass())

    }
}
