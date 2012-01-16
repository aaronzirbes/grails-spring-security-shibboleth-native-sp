package edu.umn.shibboleth.sp

import static org.junit.Assert.*

import grails.test.mixin.*
import grails.test.mixin.support.*
import org.junit.*

/**
 * See the API for {@link grails.test.mixin.support.GrailsUnitTestMixin} for usage instructions
 */
@TestMixin(GrailsUnitTestMixin)
class ShibbolethAuthenticationTokenTests {

    void testFilterToken() {

		def authenticationMethod = 'fake.authentication.method'
		def identityProvider = 'fake.IdP'
		def authenticationInstant = '1234567890'
		def authenticationType = 'shibboleth'
		def remoteAddress = '127.0.0.1' 
		def attributes = [:]
		def eppn = 'me@example.org'

		def token = new ShibbolethAuthenticationToken(
			eppn, authenticationType, authenticationMethod, 
			identityProvider, authenticationInstant, 
			remoteAddress, attributes)

		assert authenticationMethod == token.getAuthenticationMethod()
		assert identityProvider == token.getIdentityProvider()
		assert authenticationInstant == token.getAuthenticationInstant()
		assert authenticationType == token.getAuthenticationType()
		assert remoteAddress == token.getRemoteAddress()
		assert attributes == token.getAttributes()
		assert eppn == token.getEppn()
		assert eppn == token.getPrincipal()
		assertNull token.getDetails()

		assertFalse token.isAuthenticated()
    }

    void testProviderToken() {

		def authenticationMethod = 'fake.authentication.method'
		def identityProvider = 'fake.IdP'
		def authenticationInstant = '1234567890'
		def authenticationType = 'shibboleth'
		def remoteAddress = '127.0.0.1' 
		def attributes = [:]
		def eppn = 'me@example.org'
		def principal = 'me@example.org'
		def authorities = []
		def details = null

		def token = new ShibbolethAuthenticationToken(
			authorities, details, principal, eppn, 
			authenticationType, authenticationMethod, 
			identityProvider, authenticationInstant, 
			remoteAddress, attributes)

		assert authenticationMethod == token.getAuthenticationMethod()
		assert identityProvider == token.getIdentityProvider()
		assert authenticationInstant == token.getAuthenticationInstant()
		assert authenticationType == token.getAuthenticationType()
		assert remoteAddress == token.getRemoteAddress()
		assert attributes == token.getAttributes()
		assert eppn == token.getEppn()
		assert principal == token.getPrincipal()
		assert authorities == token.getAuthorities()
		assert details == token.getDetails()
		
		assertTrue token.isAuthenticated()
    }
}
