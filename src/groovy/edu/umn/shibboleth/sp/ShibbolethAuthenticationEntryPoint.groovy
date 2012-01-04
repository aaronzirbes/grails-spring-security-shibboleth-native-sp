package edu.umn.shibboleth.sp

import java.net.URLEncoder
import java.io.IOException

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.beans.factory.InitializingBean
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.util.Assert

class ShibbolethAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {

	/** This is the SP login URL, typically this is '/Shibboleth.sso/Login', but you 
	can change it if your implementation is different */
	String loginUrl = '/Shibboleth.sso/Login'
	String targetVariable = 'target'

	public void afterPropertiesSet() throws Exception {
		Assert.hasLength(loginUrl, "loginUrl must be specified")
		Assert.hasLength(targetVariable, "targetVariable must be specified")
	}

	public final void commence(final HttpServletRequest servletRequest, final HttpServletResponse response,
	final AuthenticationException authenticationException) throws IOException, ServletException {

		final String redirectUrl = createRedirectUrl(servletRequest, response)

		preCommence(servletRequest, response)

		response.sendRedirect(redirectUrl)
	}

	private String createRedirectUrl(final HttpServletRequest request, final HttpServletResponse response) {
		String uri = request.getRequestURI()
		String returnUrl = URLEncoder.encode(uri.toString(), "ISO-8859-1")
		return loginUrl + '?' + targetVariable + '=' + returnUrl
	}

	/**
	 * Template method for you to do your own pre-processing before the redirect occurs.
	 *
	 * @param request the HttpServletRequest
	 * @param response the HttpServletResponse
	 */
	protected void preCommence(final HttpServletRequest request, final HttpServletResponse response) {

	}
}
