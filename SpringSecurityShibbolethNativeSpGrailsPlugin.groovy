import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

class SpringSecurityShibbolethNativeSpGrailsPlugin {
    // the plugin version
    def version = "0.9"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "1.3.7 > *"
    // the other plugins this plugin depends on
    Map  dependsOn = [springSecurityCore: '1.1.1 > *']
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
		'grails-app/domain/**',
		'docs/**',
		'src/docs/**',
		'test/**'
    ]

    // TODO Fill in these fields
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

		if (application.warDeployed) {
			// need to load secondary here since web.xml was already built, so
			// doWithWebDescriptor isn't called when deployed as war

			SpringSecurityUtils.loadSecondaryConfig 'DefaultShibbolethSecurityConfig'
			conf = SpringSecurityUtils.securityConfig
			if (!conf.shibboleth.active) { return }
		}

		println 'Configuring Spring Security CAS ...'

		SpringSecurityUtils.registerProvider 'shibbolethAuthenticationProvider'
		SpringSecurityUtils.registerFilter 'shibbolethAuthenticationFilter', SecurityFilterPosition.CAS_FILTER + 20

		  // custom authentication filter 
		shibbolethAuthenticationFilter(ShibbolethAuthenticationFilter) {
			authenticationManager = ref('authenticationManager')
			sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
			authenticationSuccessHandler = ref('authenticationSuccessHandler')
			authenticationFailureHandler = ref('authenticationFailureHandler')
			rememberMeServices = ref('rememberMeServices')
			authenticationDetailsSource = ref('authenticationDetailsSource')                                               

			principalUsernameAttribute = conf.shibboleth.principalUsername.attribute
			authenticationMethodAttribute = conf.shibboleth.authenticationMethod.attribute
			identityProviderAttribute = conf.shibboleth.identityProvider.attribute                                         
			authenticationInstantAttribute = conf.shibboleth.authenticationInstant.attribute                               
			developmentEnvironment = conf.shibboleth.development.environment
			extraAttributes = conf.shibboleth.extraAttributes
		}

		// custom authentication provider
		shibbolethAuthenticationProvider(ShibbolethAuthenticationProvider) {
			userDetailsService = ref('shibbolethUserDetailsService')                                                       
			identityProviderAllowed = conf.shibboleth.identityProvider.attribute
			authenticationMethodAllowed = conf.shibboleth.authenticationMethod.allowed                                     
		}   

		// custom user details service
		shibbolethUserDetailsService(ShibbolethUserDetailsService) {
			rolesAttribute = conf.shibboleth.roles.attribute
			rolesSeparator = conf.shibboleth.roles.separator
			rolesPrefix = conf.shibboleth.roles.prefix
			authenticationMethodRoles = conf.shibboleth.authenticationMethod.roles
			ipAddressRoles = conf.remoteaddress.roles
			developmentRoles = conf.shibboleth.development.roles                                                           
		}       

		// custom authentication entry point                                                                               
		authenticationEntryPoint(ShibbolethAuthenticationEntryPoint) {
			loginUrl = conf.shibboleth.loginUrl
			targetVariable = conf.shibboleth.loginTargetVariable
		}               
    }
}
