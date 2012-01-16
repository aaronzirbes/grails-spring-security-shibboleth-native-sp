package edu.umn.shibboleth.sp

import static org.junit.Assert.*

import org.springframework.security.core.authority.AuthorityUtils
import grails.test.mixin.*
import grails.test.mixin.support.*
import org.junit.*

/**
 * See the API for {@link grails.test.mixin.support.GrailsUnitTestMixin} for usage instructions
 */
@TestMixin(GrailsUnitTestMixin)
class ShibbolethUserDetailsTests {

    void testUserDetailsInstantiation() {
		def enabled = true
		def authorities = AuthorityUtils.createAuthorityList("ROLE_USER")
		def eppn = 'me@example.org'
		def username = eppn
		def attributes = ['someattribute': 'some value']

		def shibbolethUser = new ShibbolethUserDetails( username, 
			enabled, authorities, eppn, attributes)

		assert eppn == shibbolethUser.username
		assert eppn == shibbolethUser.eppn
		assert "some value" == shibbolethUser.attributes['someattribute']
		assertTrue shibbolethUser.enabled
		assertTrue shibbolethUser.authorities.collect{ it.toString() }.contains('ROLE_USER')
    }
}
