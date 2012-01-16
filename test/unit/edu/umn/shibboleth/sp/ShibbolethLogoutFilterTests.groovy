package edu.umn.shibboleth.sp

import static org.junit.Assert.*

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockFilterChain
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler

import grails.test.mixin.*
import grails.test.mixin.support.*
import org.junit.*

/**
 * See the API for {@link grails.test.mixin.support.GrailsUnitTestMixin} for usage instructions
 */
@TestMixin(GrailsUnitTestMixin)
class ShibbolethLogoutFilterTests {

	def filterParams
	def testingToken
	def shibbolethAuthenticationToken
	def changedShibbolethAuthenticationToken
	def logoutHandler

    void setUp() {
        // Setup logic here

		// Logout Handler
		logoutHandler = new SecurityContextLogoutHandler()

		filterParams = [
			principalUsernameAttribute: 'EPPN',
			authenticationMethodAttribute: 'Shib-Authentication-Method',
			identityProviderAttribute: 'Shib-Identity-Provider',
			handlers: [ logoutHandler ] ]

		// Non-Shib Token
		testingToken = new TestingAuthenticationToken("user", "password", "ROLE_A")

		// Shib Token attributes
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

		// Shib Token
		shibbolethAuthenticationToken = new ShibbolethAuthenticationToken(
			authorities, details, principal, eppn, 
			authenticationType, authenticationMethod, 
			identityProvider, authenticationInstant, 
			remoteAddress, attributes)

		// Slightly altered shib token
		authenticationMethod = 'changed.authentication.method'

		changedShibbolethAuthenticationToken = new ShibbolethAuthenticationToken(
			authorities, details, principal, eppn, 
			authenticationType, authenticationMethod, 
			identityProvider, authenticationInstant, 
			remoteAddress, attributes)

    }

	void testAfterPropertiesSetEppn() {
		// fail if principalUsernameAttribute is missing
		shouldFail{
			def logoutFilter = new ShibbolethLogoutFilter(
				authenticationMethodAttribute: 'Shib-Authentication-Method',
				identityProviderAttribute: 'Shib-Identity-Provider')
			logoutFilter.afterPropertiesSet()
		}
	}

	void testAfterPropertiesSetAuthMethod() {
		// fail if authenticationMethodAttribute is missing
		shouldFail{
			def logoutFilter = new ShibbolethLogoutFilter(
				principalUsernameAttribute: 'EPPN',
				identityProviderAttribute: 'Shib-Identity-Provider')
			logoutFilter.afterPropertiesSet()
		}
	}

	void testAfterPropertiesSetIdP() {
		// fail if identityProviderAttribute is missing
		shouldFail{
			def logoutFilter = new ShibbolethLogoutFilter(
				principalUsernameAttribute: 'EPPN',
				authenticationMethodAttribute: 'Shib-Authentication-Method')
			logoutFilter.afterPropertiesSet()
		}
	}
	
	void testFilterNoAuth() {

		// Mock up Request/Response
		def request = new MockHttpServletRequest('GET', '/')
		def response = new MockHttpServletResponse()

		def shibbolethLogoutFilter = new ShibbolethLogoutFilter(filterParams)

		// Put a test token in the security context holder
		SecurityContextHolder.getContext().setAuthentication(testingToken)

		// Run the filter
		shibbolethLogoutFilter.doFilter(request, response, new MockFilterChain())

		// get the token back
		def auth = SecurityContextHolder.getContext().getAuthentication()

		assert auth == testingToken
	}

	void testFilterShibNoChange() {
		// Mock up Request/Response
		def request = new MockHttpServletRequest('GET', '/')
		def response = new MockHttpServletResponse()

		def shibbolethLogoutFilter = new ShibbolethLogoutFilter(filterParams)

		// set up the request parameters
		def authenticationMethod = 'fake.authentication.method'
		def identityProvider = 'fake.IdP'
		def authenticationType = 'shibboleth'
		def remoteAddress = '127.0.0.1' 
		def eppn = 'me@example.org'
		request.setAuthType(authenticationType)
		request.setRemoteUser(eppn)
		request.setRemoteAddr(remoteAddress)
		request.setAttribute('EPPN', eppn)
		request.setAttribute('Shib-Authentication-Method', authenticationMethod)
		request.setAttribute('Shib-Identity-Provider', identityProvider)

		// Put a test token in the security context holder
		SecurityContextHolder.getContext().setAuthentication(shibbolethAuthenticationToken)

		// Run the filter
		shibbolethLogoutFilter.doFilter(request, response, new MockFilterChain())

		// get the token back
		def auth = SecurityContextHolder.getContext().getAuthentication()

		// make sure it's the same
		assert auth == shibbolethAuthenticationToken
	}

	void testFilterShibChanged() {
		// Mock up Request/Response
		def request = new MockHttpServletRequest('GET', '/')
		def response = new MockHttpServletResponse()

		def shibbolethLogoutFilter = new ShibbolethLogoutFilter(filterParams)

		// set up the request parameters
		def authenticationMethod = 'fake.authentication.method'
		def identityProvider = 'fake.IdP'
		def authenticationType = 'shibboleth'
		def remoteAddress = '127.0.0.1' 
		def eppn = 'me@example.org'
		request.setAuthType(authenticationType)
		request.setRemoteUser(eppn)
		request.setRemoteAddr(remoteAddress)
		request.setAttribute('EPPN', eppn)
		request.setAttribute('Shib-Authentication-Method', authenticationMethod)
		request.setAttribute('Shib-Identity-Provider', identityProvider)

		// Put a test token in the security context holder
		SecurityContextHolder.getContext().setAuthentication(changedShibbolethAuthenticationToken)

		// Run the filter
		shibbolethLogoutFilter.doFilter(request, response, new MockFilterChain())

		// get the token back
		def auth = SecurityContextHolder.getContext().getAuthentication()

		// make sure it was cleared
		assert auth == null
	}
}
