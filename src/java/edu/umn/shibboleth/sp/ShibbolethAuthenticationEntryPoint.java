package edu.umn.shibboleth.sp;

import java.io.IOException;
import java.net.URLEncoder;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.Assert;
import org.apache.log4j.Logger;

/**
	Processes a login request and redirects to shibboleth login

	@author <a href="mailto:ajz@umn.edu">Aaron J. Zirbes</a>
*/
class ShibbolethAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {

	private final Logger logger = Logger.getLogger(this.getClass());

	/** This is the SP login URL, typically this is '/Shibboleth.sso/Login', but you 
	can change it if your implementation is different */
	private String loginUrl = "/Shibboleth.sso/Login?target={0}";

	/** This is where we should come back to after logging in via Shiboleth */
	private static final String securityCheckUri = "/j_spring_shibboleth_native_sp_security_check";

	public void afterPropertiesSet() throws Exception {
		Assert.hasLength(loginUrl, "loginUrl must be specified");
	}

	public final void commence(final HttpServletRequest servletRequest, final HttpServletResponse response,
			final AuthenticationException authenticationException) throws IOException, ServletException {

		final String redirectUrl = createRedirectUrl(servletRequest);

		preCommence(servletRequest, response);

		logger.debug("redirecting to: " + redirectUrl);
		response.sendRedirect(redirectUrl);
	}

	private String createRedirectUrl(final HttpServletRequest request) {
		String uri = request.getContextPath() + this.securityCheckUri;
		String returnUrl = uri;
		try {
			returnUrl = URLEncoder.encode(uri.toString(), "ISO-8859-1");
		} catch (java.io.UnsupportedEncodingException ex) {
			logger.debug("unable to encode URL using ISO-8859-1");
		}
		return this.loginUrl.replace("{0}", returnUrl);
	}

	/**
	 * Template method for you to do your own pre-processing before the redirect occurs.
	 *
	 * @param request the HttpServletRequest
	 * @param response the HttpServletResponse
	 */
	protected void preCommence(final HttpServletRequest request, final HttpServletResponse response) {
	}

	public void setLoginUrl(final String loginUrl) {
		this.loginUrl = loginUrl;
	}
}
