import edu.umn.shibboleth.sp.ShibbolethAuthenticationEntryPoint
import edu.umn.shibboleth.sp.ShibbolethUserDetailsService
import edu.umn.shibboleth.sp.ShibbolethAuthenticationProvider
import edu.umn.shibboleth.sp.ShibbolethAuthenticationFilter
import edu.umn.shibboleth.sp.ShibbolethLogoutFilter
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.plugins.springsecurity.GormUserDetailsService
import org.codehaus.groovy.grails.plugins.springsecurity.ldap.GrailsLdapAuthoritiesPopulator

class SpringSecurityShibbolethNativeSpGrailsPlugin {
    // the plugin version
    def version = "1.0.2"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "1.3.0 > *"
    // the other plugins this plugin depends on
    Map  dependsOn = [springSecurityCore: '1.2.7.2 > *']
	// Load after LDAP if installed...
	def loadAfter = ['springSecurityLdap']
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
		'grails-app/domain/**',
		'docs/**',
		'lib/**',
		'src/docs/**',
		'test/**' ]


    // Fill in these fields
    def author = "Aaron J. Zirbes"
    def authorEmail = "ajz@umn.edu"
    def title = "Shibboleth Naitive SP support for the Spring Security grails plugin."
    def description = "Shibboleth Naitive SP support for the Spring Security grails plugin."

    // URL to the plugin's documentation
    def documentation = "http://aaronzirbes.github.com/grails-spring-security-shibboleth-native-sp/"
	def license = "GPLv3"
	def developers = [ [ name: "Aaron J. Zirbes", email: "aaron.zirbes@gmail.com" ] ]
	def issueManagement = [ system: "GitHub", url: "https://github.com/aaronzirbes/grails-spring-security-shibboleth-native-sp/issues" ]
	def scm = [ url: "https://github.com/aaronzirbes/grails-spring-security-shibboleth-native-sp" ]

    def doWithSpring = {
        // plug in shibboleth artifacts in to spring security
		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) { return }

		SpringSecurityUtils.loadSecondaryConfig 'DefaultShibbolethSecurityConfig'
		conf = SpringSecurityUtils.securityConfig
		if (!conf.shibboleth.active) { return }

		println 'Configuring Spring Security Shibboleth Native SP ...'

		//Ensure all 'extra attributes' are where they need to be
		if (conf.roles.attribute && !conf.extraAttributes.contains(conf.roles.attribute)) {
			conf.extraAttributes.add(conf.roles.attribute)
		}
		if (conf.email.attribute && !conf.extraAttributes.contains(conf.email.attribute)) {
			conf.extraAttributes.add(conf.email.attribute)
		}
		if (conf.fullName.attribute && !conf.extraAttributes.contains(conf.fullName.attribute)) {
			conf.extraAttributes.add(conf.fullName.attribute)
		}

		// shibboleth authentication entry point                                                                               
		authenticationEntryPoint(ShibbolethAuthenticationEntryPoint) {
			loginUrl = conf.shibboleth.loginUrl
		}

		// shibboleth user details service
		shibbolethUserDetailsService(ShibbolethUserDetailsService) {
			emailAttribute = conf.shibboleth.email.attribute
			fullNameAttribute = conf.shibboleth.fullName.attribute
			rolesAttribute = conf.shibboleth.roles.attribute
			rolesSeparator = conf.shibboleth.roles.separator
			rolesPrefix = conf.shibboleth.roles.prefix
			authenticationMethodRoles = conf.shibboleth.authenticationMethod.roles
			identityProviderRoles = conf.shibboleth.identityProvider.roles
			ipAddressRoles = conf.remoteAddress.roles

			if (conf.ldap.active && conf.ldap.authorities.retrieveGroupRoles && conf.ldap.usernameMapper.userDnBase) {
				userDnBase = conf.ldap.usernameMapper.userDnBase
				ldapAuthoritiesPopulator = ref('ldapAuthoritiesPopulator')
			}

			if (conf.roles.loadFromUserDetailsService) {
				userDetailsService = ref('userDetailsService')
			}
		}       

		// shibboleth authentication provider
		shibbolethAuthenticationProvider(ShibbolethAuthenticationProvider) {
			if (conf.shibboleth.useShibbolethUserDetails) {
				authenticationUserDetailsService = ref('shibbolethUserDetailsService')                                                       
			} else {
				userDetailsService = ref('userDetailsService')
			}
		}   

		// shibboleth authentication filter 
		shibbolethAuthenticationFilter(ShibbolethAuthenticationFilter, conf.shibboleth.login.filterProcessesUrl) {
			authenticationDetailsSource = ref('authenticationDetailsSource')                                               
			authenticationFailureHandler = ref('authenticationFailureHandler')
			authenticationManager = ref('authenticationManager')
			authenticationSuccessHandler = ref('authenticationSuccessHandler')
			rememberMeServices = ref('rememberMeServices')
			sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')

			principalUsernameAttribute = conf.shibboleth.principalUsername.attribute
			authenticationMethodAttribute = conf.shibboleth.authenticationMethod.attribute
			identityProviderAttribute = conf.shibboleth.identityProvider.attribute                                         

			usernameAttribute = conf.shibboleth.username.attribute
			authenticationInstantAttribute = conf.shibboleth.authenticationInstant.attribute                               
			extraAttributes = conf.shibboleth.extraAttributes

			usernameStripAtDomain = conf.shibboleth.username.stripAtDomain
		}

		// shibboleth logout filter
		shibbolethLogoutFilter(ShibbolethLogoutFilter) {
			handlers = ref('logoutHandlers')

			principalUsernameAttribute = conf.shibboleth.principalUsername.attribute
			authenticationMethodAttribute = conf.shibboleth.authenticationMethod.attribute
			identityProviderAttribute = conf.shibboleth.identityProvider.attribute
		}

		// If LDAP is configured, then load authorities from LDAP
		if (conf.ldap.active && conf.ldap.authorities.retrieveGroupRoles && conf.ldap.usernameMapper.userDnBase) {
			// If the LDAP plugin is installed, enabled, and set to retreive groups, then allow loading roles from LDAP

			// Due to limitations in the LDAP user details service, only roles will be loaded
			ldapAuthoritiesPopulator(GrailsLdapAuthoritiesPopulator, contextSource, conf.ldap.authorities.groupSearchBase) {
				groupRoleAttribute = conf.ldap.authorities.groupRoleAttribute
				groupSearchFilter = conf.ldap.authorities.groupSearchFilter
				searchSubtree = conf.ldap.authorities.searchSubtree
				if (conf.ldap.authorities.defaultRole) {
					defaultRole = conf.ldap.authorities.defaultRole
				}
				ignorePartialResultException = conf.ldap.authorities.ignorePartialResultException // false
				userDetailsService = ref('userDetailsService')
				retrieveDatabaseRoles = conf.ldap.authorities.retrieveDatabaseRoles // false
				roleStripPrefix = conf.ldap.authorities.clean.prefix
				roleStripSuffix = conf.ldap.authorities.clean.suffix
				roleConvertDashes = conf.ldap.authorities.clean.dashes
				roleToUpperCase = conf.ldap.authorities.clean.uppercase
			}
		}

		SpringSecurityUtils.registerProvider 'shibbolethAuthenticationProvider'
		SpringSecurityUtils.registerFilter 'shibbolethLogoutFilter', SecurityFilterPosition.LOGOUT_FILTER.getOrder() + 10
		SpringSecurityUtils.registerFilter 'shibbolethAuthenticationFilter', SecurityFilterPosition.CAS_FILTER.getOrder() - 10

		println '...finished configuring Spring Security Shibboleth Native SP'
    }
}
