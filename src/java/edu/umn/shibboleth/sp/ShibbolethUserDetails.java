package edu.umn.shibboleth.sp;

import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * Models user information retreived by a {@link ShibbolethUserDetailsService}.
 * 
 * This adds support for eppn to the {@link User} class.
 * 
 * @author <a href="mailto:ajz@umn.edu">Aaron J. Zirbes</a>
 */
class ShibbolethUserDetails extends User {

	private String eppn;
	private Map<String, String> attributes;

	/** constructor for ShibbolethUserDetails */
	ShibbolethUserDetails(String username, boolean enabled
			Collection<GrantedAuthority> authorities, String eppn, 
			Map<String, String> attributes) {

		super(username, '', true, true, true, true, authorities);

		this.eppn = eppn;
		this.attributes = attributes;
	}

	/** returns the eppn */
	public String getEppn() { return eppn; }

	/** returns the extra attributes */
	public Map<String, String> getAttributes() { return attributes; }

}
