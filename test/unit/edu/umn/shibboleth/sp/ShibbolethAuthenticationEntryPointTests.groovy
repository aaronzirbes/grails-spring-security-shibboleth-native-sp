package edu.umn.shibboleth.sp

import static org.junit.Assert.*

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.InsufficientAuthenticationException
import grails.test.mixin.*
import grails.test.mixin.support.*
import org.junit.*

/**
 * See the API for {@link grails.test.mixin.support.GrailsUnitTestMixin} for usage instructions
 */
@TestMixin(GrailsUnitTestMixin)
class ShibbolethAuthenticationEntryPointTests {

    void testRedirect() {
		def loginUrl = '/login/TARGET={0}'
        def entryPoint = new ShibbolethAuthenticationEntryPoint(loginUrl: loginUrl)

		def request = new MockHttpServletRequest('GET', '/')
		def response = new MockHttpServletResponse()
		def authenticationException = new InsufficientAuthenticationException('TEST')

		entryPoint.commence(request, response, authenticationException)

		assertEquals "/login/TARGET=%2Fj_spring_shibboleth_native_sp_security_check", response.redirectedUrl

    }
}
