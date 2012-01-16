grails.project.groupId = 'edu.umn.shibboleth.sp' // change this to alter the default package name and Maven publishing destination

// The default codec used to encode data with ${}
grails.views.default.codec = "none" // none, html, base64
grails.views.gsp.encoding = "UTF-8"
grails.converters.encoding = "UTF-8"

// log4j configuration
log4j = {
    // Example of changing the log pattern for the default console
    // appender:
    //
    //appenders {
    //    console name:'stdout', layout:pattern(conversionPattern: '%c{2} %m%n')
    //}

    error  'org.codehaus.groovy.grails.web.servlet',  //  controllers
           'org.codehaus.groovy.grails.web.pages', //  GSP
           'org.codehaus.groovy.grails.web.sitemesh', //  layouts
           'org.codehaus.groovy.grails.web.mapping.filter', // URL mapping
           'org.codehaus.groovy.grails.web.mapping', // URL mapping
           'org.codehaus.groovy.grails.commons', // core / classloading
           'org.codehaus.groovy.grails.plugins', // plugins
           'org.codehaus.groovy.grails.orm.hibernate', // hibernate integration
           'org.springframework',
           'org.hibernate',
           'net.sf.ehcache.hibernate'

    warn   'org.mortbay.log'
}

grails.doc.license = 'GNU General Public License v3'
grails.doc.title = "Grails Spring Security Shibboleth Native SP Plugin"
grails.doc.subtitle = "Hooking spring security to the Shibboleth Native SP through Apache"
grails.doc.authors = "Aaron J. Zirbes"
grails.doc.license = "GPL v3"
grails.doc.copyright = "Copyright (c) 2012 Aaron J. Zirbes"

//*** BEGIN SHIBBOLETH CONFIGURATION SETTINGS ***/

// use this to simulate a shibboleth environment when your app is running in
// development mode.

// Used by Controllers
grails.plugins.springsecurity.shibboleth.loginUrl = '/Shibboleth.sso/Login?target={0}'
grails.plugins.springsecurity.shibboleth.logoutUrl = '/Shibboleth.sso/Logout'

// Token Attributes
grails.plugins.springsecurity.shibboleth.principalUsername.attribute = 'EPPN'
grails.plugins.springsecurity.shibboleth.authenticationMethod.attribute = 'Shib-AuthnContext-Method'
grails.plugins.springsecurity.shibboleth.identityProvider.attribute = 'Shib-Identity-Provider'
grails.plugins.springsecurity.shibboleth.authenticationInstant.attribute = 'Shib-Authentication-Instant'

// Used by Authentication Provider
grails.plugins.springsecurity.shibboleth.roles.attribute = null
grails.plugins.springsecurity.shibboleth.roles.separator = ','
grails.plugins.springsecurity.shibboleth.roles.prefix = 'SHIB_'
grails.plugins.springsecurity.shibboleth.extraAttributes = [ 'uid', 'Shib-Session-Index', 'Shib-Session-ID', 'Shib-AuthnContext-Class', 'Shib-Application-ID' ]

// This maps IdPs to authentication methods to allow for security annotations
// for securing based on originating IdP server
grails.plugins.springsecurity.shibboleth.identityProvider.roles = [
	'ROLE_IDP_UMN': 'https://idp2.shib.umn.edu/idp/shibboleth', 
	'ROLE_IDP_NORTHWESTERN': 'https://fed.it.northwestern.edu/shibboleth-idp/SSO',
	'ROLE_IDP_UMNTEST': 'https://idp-test.shib.umn.edu/idp/shibboleth' ]

// This maps roles to authentication methods to allow for security annotations
// for securing based on method
grails.plugins.springsecurity.shibboleth.authenticationMethod.roles = [
	'ROLE_AUTH_METHOD_STANDARD': 'urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified',
	'ROLE_AUTH_METHOD_UMN_MKEY': 'https://www.umn.edu/shibboleth/classes/authncontext/mkey' ]
// grails.plugins.springsecurity.shibboleth.authenticationMethod.roles = null

// Allow location based roles
grails.plugins.springsecurity.remoteAddress.roles = [
	'ROLE_IP_UMN_VPN': ['134.84.0.0/23'], 
	'ROLE_IP_UMN_CAMPUS': ['160.94.0.0/16', '128.101.0.0/16', '134.84.0.0/16'], 
	'ROLE_IP_UMN_DEPT': ['160.94.224.0/25', '128.101.60.128/25', '134.84.107.192/26'] ]


