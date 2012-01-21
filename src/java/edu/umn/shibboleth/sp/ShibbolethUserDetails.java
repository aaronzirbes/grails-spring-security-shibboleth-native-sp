package edu.umn.shibboleth.sp;

import java.util.Collection;
import java.util.Map;
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
	private String fullName;
	private String email;
	private Map<String, String> attributes;

	/** constructor for ShibbolethUserDetails */
	public ShibbolethUserDetails(String username, 
			String email, String fullName, 
			Collection<GrantedAuthority> authorities, String eppn, 
			Map<String, String> attributes) {

		super(username, "", true, true, true, true, authorities);

		this.eppn = eppn;
		this.email = email;
		this.fullName = fullName;
		this.attributes = attributes;
	}

	/** returns the eppn */
	public String getEppn() { return eppn; }

	/** returns the email */
	public String getEmail() { return email; }

	/** returns the fullName */
	public String getFullName() { return fullName; }

	/** returns the extra attributes */
	public Map<String, String> getAttributes() { return attributes; }

}
