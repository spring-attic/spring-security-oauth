package org.springframework.security.oauth2.provider;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.web.bind.annotation.SessionAttributes;

/**
 * A request for authorization by an OAuth 2 Client, normally received and
 * processed by the AuthorizationEndpoint. This class is meant to be manipulated
 * throughout the authorization process, and is therefore treated as ephemeral
 * and not to be stored long term. For long term storage, use the read-only
 * {@link OAuth2Request} class.
 * 
 * HTTP request parameters are stored in the parameters map, and any processing
 * the server makes throughout the lifecycle of a request are stored on
 * individual properties. The original request parameters will remain available
 * through the parameters map. For convenience, constants are defined in order
 * to get at those original values. However, the parameters map is unmodifiable
 * so that processing cannot drop the original values.
 * 
 * This class is {@link Serializable} in order to support storage of the
 * authorization request as a {@link SessionAttributes} member while the end
 * user through the authorization process (which may span several page
 * requests).
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 * @author Amanda Anganes
 */
@SuppressWarnings("serial")
public class AuthorizationRequest extends BaseRequest implements Serializable {

	/**
	 * Map to hold the original, unchanged parameter set submitted by a user to
	 * signal approval of the token grant approval. Once set this should not be
	 * modified.
	 */
	private Map<String, String> approvalParameters = Collections.unmodifiableMap(new HashMap<String, String>());

	/**
	 * The value of the "state" parameter sent by the client in the request, if
	 * sent by the client. As this must be echoed back to the client unchanged,
	 * it should not be modified by any processing classes.
	 */
	private String state;

	/**
	 * Resolved requested response types initialized (by the
	 * OAuth2RequestFactory) with the response types originally requested.
	 */
	private Set<String> responseTypes = new HashSet<String>();

	/**
	 * Resolved resource IDs. This set may change during request processing.
	 */
	private Set<String> resourceIds = new HashSet<String>();

	/**
	 * Resolved granted authorities for this request. May change during request
	 * processing.
	 */
	private Collection<? extends GrantedAuthority> authorities = new HashSet<GrantedAuthority>();

	/**
	 * Whether the request has been approved by the end user (or other process).
	 * This will be altered by the User Approval Endpoint and/or the
	 * UserApprovalHandler as appropriate.
	 */
	private boolean approved = false;

	/**
	 * The resolved redirect URI of this request. A URI may be present in the
	 * original request, in the authorizationParameters, or it may not be
	 * provided, in which case it will be defaulted (by processing classes) to
	 * the Client's default registered value.
	 */
	private String redirectUri;

	/**
	 * Extension point for custom processing classes which may wish to store
	 * additional information about the OAuth2 request. Since this class will
	 * create a serializable OAuth2Request, all members of this extension map
	 * must be serializable.
	 */
	private Map<String, Serializable> extensions = new HashMap<String, Serializable>();

	/**
	 * Default constructor.
	 */
	public AuthorizationRequest() {
	}

	/**
	 * Full constructor.
	 */
	public AuthorizationRequest(Map<String, String> authorizationParameters, Map<String, String> approvalParameters, String clientId, Set<String> scope, Set<String> resourceIds, Collection<? extends GrantedAuthority> authorities, boolean approved, String state, String redirectUri,
	        Set<String> responseTypes) {
		setClientId(clientId);
		setRequestParameters(authorizationParameters); // in case we need to
													   // wrap the collection
		setScope(scope); // in case we need to parse
		if (resourceIds != null) {
			this.resourceIds = new HashSet<String>(resourceIds);
		}
		if (authorities != null) {
			this.authorities = new HashSet<GrantedAuthority>(authorities);
		}
		this.approved = approved;
		this.resourceIds = resourceIds;
		this.redirectUri = redirectUri;
		if (responseTypes != null) {
			this.responseTypes = responseTypes;
		}
		this.state = state;
	}

	public OAuth2Request createOAuth2Request() {
		return new OAuth2Request(getRequestParameters(), getClientId(), getAuthorities(), isApproved(), getScope(), getResourceIds(), getRedirectUri(), getResponseTypes(), getExtensions());
	}

	/**
	 * Convenience constructor for unit tests, where client ID and scope are
	 * often the only needed fields.
	 * 
	 * @param clientId
	 * @param scopes
	 */
	public AuthorizationRequest(String clientId, Collection<String> scopes) {
		setClientId(clientId);
		setScope(scopes); // in case we need to parse
	}

	/**
	 * Convenience method to set resourceIds and authorities on this request by
	 * inheriting from a ClientDetails object.
	 * 
	 * @param clientDetails
	 */
	public void setResourceIdsAndAuthoritiesFromClientDetails(ClientDetails clientDetails) {
		setResourceIds(clientDetails.getResourceIds());
		setAuthorities(clientDetails.getAuthorities());
	}

	public Map<String, String> getApprovalParameters() {
		return approvalParameters;
	}

	public void setApprovalParameters(Map<String, String> approvalParameters) {
		this.approvalParameters = approvalParameters;
	}

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}

	public Set<String> getResponseTypes() {
		return responseTypes;
	}

	public void setResponseTypes(Set<String> responseTypes) {
		this.responseTypes = responseTypes;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public void setApproved(boolean approved) {
		this.approved = approved;
	}

	public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
		if (authorities != null) {
			this.authorities = new HashSet<GrantedAuthority>(authorities);
		}
	}

	/**
	 * @return the extensions
	 */
	public Map<String, Serializable> getExtensions() {
		return extensions;
	}

	public void setExtensions(Map<String, Serializable> extensions) {
		this.extensions = extensions;
	}

	public void setResourceIds(Set<String> resourceIds) {
		this.resourceIds = resourceIds;
	}

	public void setClientId(String clientId) {
		super.setClientId(clientId);
	}

	/**
	 * Set the scope value. If the collection contains only a single scope
	 * value, this method will parse that value into a collection using
	 * {@link OAuth2Utils#parseParameterList}.
	 * 
	 * @see TokenRequest#setScope
	 * 
	 * @param scope
	 */
	public void setScope(Collection<String> scope) {
		super.setScope(scope);
	}

	/**
	 * Set the Request Parameters on this authorization request, which represent
	 * the original request parameters and should never be changed during
	 * processing. The map passed in is wrapped in an unmodifiable map instance.
	 * 
	 * @see TokenRequest#setRequestParameters
	 * 
	 * @param requestParameters
	 */
	public void setRequestParameters(Map<String, String> requestParameters) {
		super.setRequestParameters(requestParameters);
	}

	/**
	 * @return the resourceIds
	 */
	public Set<String> getResourceIds() {
		return resourceIds;
	}

	/**
	 * @return the authorities
	 */
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	/**
	 * @return the approved
	 */
	public boolean isApproved() {
		return approved;
	}

	/**
	 * @return the redirectUri
	 */
	public String getRedirectUri() {
		return redirectUri;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((approvalParameters == null) ? 0 : approvalParameters.hashCode());
		result = prime * result + ((responseTypes == null) ? 0 : responseTypes.hashCode());
		result = prime * result + ((state == null) ? 0 : state.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		AuthorizationRequest other = (AuthorizationRequest) obj;
		if (approvalParameters == null) {
			if (other.approvalParameters != null)
				return false;
		} else if (!approvalParameters.equals(other.approvalParameters))
			return false;
		if (responseTypes == null) {
			if (other.responseTypes != null)
				return false;
		} else if (!responseTypes.equals(other.responseTypes))
			return false;
		if (state == null) {
			if (other.state != null)
				return false;
		} else if (!state.equals(other.state))
			return false;
		return true;
	}

}