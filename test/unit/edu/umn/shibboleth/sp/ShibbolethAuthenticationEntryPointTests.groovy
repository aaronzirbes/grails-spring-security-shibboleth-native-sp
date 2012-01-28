package edu.umn.shibboleth.sp

import static org.junit.Assert.*

import java.net.URLEncoder
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

	void testAfterPropertiesFailure() {
		def entryPoint = new ShibbolethAuthenticationEntryPoint(loginUrl: '')
		shouldFail {
			entryPoint.afterPropertiesSet()
		}
	}

	void testEncodingFailure() {
		def loginUrl = '/login/TARGET={0}'
        def entryPoint = new ShibbolethAuthenticationEntryPoint(
			loginUrl: loginUrl,
			utfEncoding: 'FAIL')

		def request = new MockHttpServletRequest('GET', '/')
		def response = new MockHttpServletResponse()
		def authenticationException = new InsufficientAuthenticationException('TEST')

		entryPoint.commence(request, response, authenticationException)
	}

    void testRedirect() throws UnsupportedEncodingException {
		def loginUrl = '/login/TARGET={0}'
        def entryPoint = new ShibbolethAuthenticationEntryPoint(loginUrl: loginUrl)
		entryPoint.afterPropertiesSet()

		def request = new MockHttpServletRequest('GET', '/')
		def response = new MockHttpServletResponse()
		def authenticationException = new InsufficientAuthenticationException('TEST')

		entryPoint.commence(request, response, authenticationException)
		def urlTarget = URLEncoder.encode("http://localhost:80/j_spring_shibboleth_native_sp_security_check", "UTF-8")
		def url = "/login/TARGET=${urlTarget}".toString()

		assertEquals url, response.redirectedUrl

    }
}
