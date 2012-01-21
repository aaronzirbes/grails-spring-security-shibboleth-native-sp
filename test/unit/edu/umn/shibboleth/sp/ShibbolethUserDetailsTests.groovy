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
		def authorities = AuthorityUtils.createAuthorityList("ROLE_USER")
		def username = 'testuser'
		def eppn = username + '@example.org'
		def email = eppn
		def fullName = 'Test P. User'
		def attributes = ['someattribute': 'some value']

		def shibbolethUser = new ShibbolethUserDetails( username, 
			email, fullName, authorities, eppn, attributes)

		assert username == shibbolethUser.username
		assert eppn == shibbolethUser.eppn
		assert email == shibbolethUser.email
		assert fullName == shibbolethUser.fullName
		assert "some value" == shibbolethUser.attributes['someattribute']
		assertTrue shibbolethUser.enabled
		assertTrue shibbolethUser.authorities.collect{ it.toString() }.contains('ROLE_USER')
    }
}
