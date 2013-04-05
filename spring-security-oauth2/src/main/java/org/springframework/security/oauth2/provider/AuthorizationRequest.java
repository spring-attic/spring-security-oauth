package org.springframework.security.oauth2.provider;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

/**
 * Base class representing a request for authorization. There are convenience methods for the well-known properties
 * required by the OAUth2 spec, and a set of generic authorizationParameters to allow for extensions.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 * @author Amanda Anganes
 */
public interface AuthorizationRequest {

	public static final String CLIENT_ID = "client_id";

	public static final String STATE = "state";

	public static final String SCOPE = "scope";

	public static final String REDIRECT_URI = "redirect_uri";

	public static final String RESPONSE_TYPE = "response_type";

	public static final String USER_OAUTH_APPROVAL = "user_oauth_approval";

	public Map<String, String> getAuthorizationParameters();
	
	public void setAuthorizationParameters(Map<String, String> authorizationParameters);
	
	public Map<String, String> getApprovalParameters();
	
	public void setApprovalParameters(Map<String, String> approvalParameters);

	public String getClientId();
	
	public void setClientId();

	public Set<String> getScope();
	
	public void setScope(Set<String> scope);

	public Set<String> getResourceIds();
	
	public void setResourceIds(Set<String> resourceIds);

	public Collection<GrantedAuthority> getAuthorities();
	
	public void setAuthorities(Collection<GrantedAuthority> authorities);

	public boolean isApproved();
	
	public void setApproved(boolean approved);

	public boolean isDenied();
	
	public void setDenied(boolean denied);

	public String getState();
	
	public void setState(String state);

	public String getRedirectUri();
	
	public void setRedirectUri(String redirectUri);

	public Set<String> getResponseTypes();
	
	public void setResponseTypes(Set<String> responseTypes);

}