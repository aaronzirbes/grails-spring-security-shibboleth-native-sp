package edu.umn.shibboleth.sp

import static org.junit.Assert.*

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.authority.AuthorityUtils
import grails.test.mixin.*
import grails.test.mixin.support.*
import org.junit.*

/**
 * See the API for {@link grails.test.mixin.support.GrailsUnitTestMixin} for usage instructions
 */
@TestMixin(GrailsUnitTestMixin)
class ShibbolethUserDetailsTests {

    void setUp() {
        // Setup logic here
    }

    void tearDown() {
        // Tear down logic here
    }

    void testUserDetailsInstantiation() {
		def username = 'me@example.org'
		def password = ''
		def enabled = true
		def accountNonExpired = true
		def credentialsNonExpired = true
		def accountNonLocked = true
		def authorities = AuthorityUtils.createAuthorityList("ROLE_USER")
		def eppn = 'me@example.org'
		def attributes = [:]

		def shibbolethUser = new ShibbolethUserDetails( username, password,
			enabled, accountNonExpired, credentialsNonExpired, accountNonLocked,
			authorities, eppn, attributes)

		assert shibbolethUser
    }
}
