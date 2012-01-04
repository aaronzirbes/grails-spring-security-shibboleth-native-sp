package edu.umn.shibboleth.sp

import java.util.Collection
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User

/**
Models user information retreived by a {@link ShibbolethUserDetailsService}.

This adds support for fullname, email to the {@link User} class.

@author <a href="mailto:ajz@umn.edu">Aaron J. Zirbes</a>
 */

class ShibbolethUserDetails extends User {

	private String eppn
	private Map<String, String> attributes

	ShibbolethUserDetails(String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<GrantedAuthority> authorities, String eppn, Map<String, String> attributes) {

		super(username, password, enabled, accountNonExpired, credentialsNonExpired,
			accountNonLocked, authorities)

		this.eppn = eppn
		this.attributes = attributes
	}

	public String getEppn() { return eppn }
	public Map<String, String> getAttributes() { return attributes }
}
