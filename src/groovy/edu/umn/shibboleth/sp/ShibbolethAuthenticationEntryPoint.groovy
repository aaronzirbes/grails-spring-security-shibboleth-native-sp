package edu.umn.shibboleth.sp

import java.io.IOException
import java.net.URLEncoder
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.apache.log4j.Logger
import org.springframework.beans.factory.InitializingBean
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.util.Assert

/**
	Processes a login request and redirects to shibboleth login

	@author <a href="mailto:ajz@umn.edu">Aaron J. Zirbes</a>
*/
class ShibbolethAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {

	private static final log = Logger.getLogger(this)

	/** This is the SP login URL, typically this is '/Shibboleth.sso/Login', but you 
	can change it if your implementation is different */
	String loginUrl = '/Shibboleth.sso/Login?target={0}'

	public void afterPropertiesSet() throws Exception {
		Assert.hasLength(loginUrl, "loginUrl must be specified")
	}

	public final void commence(final HttpServletRequest servletRequest, final HttpServletResponse response,
			final AuthenticationException authenticationException) throws IOException, ServletException {

		log.debug("commence():: invocation")

		final String redirectUrl = createRedirectUrl(servletRequest, response)

		preCommence(servletRequest, response)

		response.sendRedirect(redirectUrl)
	}

	private String createRedirectUrl(final HttpServletRequest request, final HttpServletResponse response) {
		String uri = request.getRequestURI()
		String returnUrl = URLEncoder.encode(uri.toString(), "ISO-8859-1")
		return loginUrl.replace("{0}", returnUrl)
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
