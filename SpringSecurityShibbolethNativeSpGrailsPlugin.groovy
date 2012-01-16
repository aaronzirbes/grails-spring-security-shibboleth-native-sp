import edu.umn.shibboleth.sp.*
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

class SpringSecurityShibbolethNativeSpGrailsPlugin {
    // the plugin version
    def version = "0.9.16"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "1.3.0 > *"
    // the other plugins this plugin depends on
    Map  dependsOn = [springSecurityCore: '1.2.1 > *']
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
		'grails-app/domain/**',
		'docs/**',
		'src/docs/**',
		'test/**'
    ]

    // Fill in these fields
    def author = "Aaron J. Zirbes"
    def authorEmail = "ajz@umn.edu"
    def title = "Shibboleth Naitive SP support for the Spring Security grails plugin."
    def description = "Shibboleth Naitive SP support for the Spring Security grails plugin."

    // URL to the plugin's documentation
    def documentation = "http://grails.org/plugin/spring-security-shibboleth-native-sp"

    def doWithSpring = {
        // plug in shibboleth artifacts in to spring security
		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) { return }

		SpringSecurityUtils.loadSecondaryConfig 'DefaultShibbolethSecurityConfig'
		conf = SpringSecurityUtils.securityConfig
		if (!conf.shibboleth.active) { return }

		println 'Configuring Spring Security Shibboleth Native SP ...'

		// shibboleth authentication entry point                                                                               
		authenticationEntryPoint(ShibbolethAuthenticationEntryPoint) {
			loginUrl = conf.shibboleth.loginUrl
		}

		// shibboleth user details service
		shibbolethUserDetailsService(ShibbolethUserDetailsService) {
			rolesAttribute = conf.shibboleth.roles.attribute
			rolesSeparator = conf.shibboleth.roles.separator
			rolesPrefix = conf.shibboleth.roles.prefix
			authenticationMethodRoles = conf.shibboleth.authenticationMethod.roles
			identityProviderRoles = conf.shibboleth.identityProvider.roles
			ipAddressRoles = conf.remoteAddress.roles
		}       

		// shibboleth authentication provider
		shibbolethAuthenticationProvider(ShibbolethAuthenticationProvider) {
			authenticationUserDetailsService = ref('shibbolethUserDetailsService')                                                       
		}   

		// shibboleth authentication filter 
		shibbolethAuthenticationFilter(ShibbolethAuthenticationFilter) {
			authenticationDetailsSource = ref('authenticationDetailsSource')                                               
			authenticationFailureHandler = ref('authenticationFailureHandler')
			authenticationManager = ref('authenticationManager')
			authenticationSuccessHandler = ref('authenticationSuccessHandler')
			rememberMeServices = ref('rememberMeServices')
			sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')

			principalUsernameAttribute = conf.shibboleth.principalUsername.attribute
			authenticationMethodAttribute = conf.shibboleth.authenticationMethod.attribute
			identityProviderAttribute = conf.shibboleth.identityProvider.attribute                                         
			authenticationInstantAttribute = conf.shibboleth.authenticationInstant.attribute                               
			extraAttributes = conf.shibboleth.extraAttributes
		}

		// shibboleth logout filter
		shibbolethLogoutFilter(ShibbolethLogoutFilter) {
			handlers = ref('logoutHandlers')

			principalUsernameAttribute = conf.shibboleth.principalUsername.attribute
			authenticationMethodAttribute = conf.shibboleth.authenticationMethod.attribute
			identityProviderAttribute = conf.shibboleth.identityProvider.attribute
		}


		SpringSecurityUtils.registerProvider 'shibbolethAuthenticationProvider'
		SpringSecurityUtils.registerFilter 'shibbolethLogoutFilter', SecurityFilterPosition.LOGOUT_FILTER.getOrder() + 10
		SpringSecurityUtils.registerFilter 'shibbolethAuthenticationFilter', SecurityFilterPosition.CAS_FILTER.getOrder() - 10

		println '...finished configuring Spring Security Shibboleth Native SP'
    }
}
