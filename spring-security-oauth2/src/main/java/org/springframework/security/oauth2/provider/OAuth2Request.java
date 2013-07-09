package org.springframework.security.oauth2.provider;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;

/**
 * Represents a stored authorization or token request. Used as part of the OAuth2Authentication object to store a
 * request's authentication information.
 * 
 * @author Amanda Anganes
 * 
 */
public class OAuth2Request extends BaseRequest implements Serializable {

	private static final long serialVersionUID = 1L;

	/**
	 * Resolved resource IDs. This set may change during request processing.
	 */
	private Set<String> resourceIds = new HashSet<String>();

	/**
	 * Resolved granted authorities for this request. May change during request processing.
	 */
	private Collection<? extends GrantedAuthority> authorities = new HashSet<GrantedAuthority>();

	/**
	 * Whether the request has been approved by the end user (or other process). This will be altered by the User
	 * Approval Endpoint and/or the UserApprovalHandler as appropriate.
	 */
	private boolean approved = false;

	/**
	 * The resolved redirect URI of this request. A URI may be present in the original request, in the
	 * authorizationParameters, or it may not be provided, in which case it will be defaulted (by processing classes) to
	 * the Client's default registered value.
	 */
	private String redirectUri;

	/**
	 * Extension point for custom processing classes which may wish to store additional information about the OAuth2
	 * request. Since this class is serializable, all members of this map must also be serializable.
	 */
	private Map<String, Serializable> extensionProperties = new HashMap<String, Serializable>();

	protected OAuth2Request(Map<String, String> requestParameters, String clientId,
			Collection<? extends GrantedAuthority> authorities, boolean approved, Set<String> scope,
			Set<String> resourceIds, String redirectUri, Map<String, Serializable> extensionProperties) {
		super(clientId);
		setRequestParameters(requestParameters);
		setScope(scope);
		if (resourceIds != null) {
			this.resourceIds = new HashSet<String>(resourceIds);
		}
		if (authorities != null) {
			this.authorities = new HashSet<GrantedAuthority>(authorities);
		}
		this.approved = approved;
		this.resourceIds = resourceIds;
		this.redirectUri = redirectUri;
		if (extensionProperties != null) {
			this.extensionProperties = extensionProperties;
		}
	}

	protected OAuth2Request(OAuth2Request other) {
		this(other.getRequestParameters(), other.getClientId(), other.getAuthorities(), other.isApproved(), other
				.getScope(), other.getResourceIds(), other.getRedirectUri(), other.getExtensionProperties());
	}

	protected OAuth2Request(String clientId) {
		super(clientId);
	}

	protected OAuth2Request() {
		super("<NOCLIENT>");
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
		this.authorities = authorities;
	}

	public boolean isApproved() {
		return approved;
	}

	public void setApproved(boolean approved) {
		this.approved = approved;
	}

	public Set<String> getResourceIds() {
		return resourceIds;
	}

	public void setResourceIds(Set<String> resourceIds) {
		this.resourceIds = resourceIds;
	}

	public Map<String, Serializable> getExtensionProperties() {
		return extensionProperties;
	}

	public void setExtensionProperties(Map<String, Serializable> extensionProperties) {
		this.extensionProperties = extensionProperties;
	}

	// FIXME: is this needed?
	public OAuth2Request createOAuth2Request(Map<String, String> parameters) {
		return new OAuth2Request(parameters, getClientId(), authorities, approved, getScope(), resourceIds,
				redirectUri, extensionProperties);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (approved ? 1231 : 1237);
		result = prime * result + ((authorities == null) ? 0 : authorities.hashCode());
		result = prime * result + ((extensionProperties == null) ? 0 : extensionProperties.hashCode());
		result = prime * result + ((redirectUri == null) ? 0 : redirectUri.hashCode());
		result = prime * result + ((resourceIds == null) ? 0 : resourceIds.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		OAuth2Request other = (OAuth2Request) obj;
		if (approved != other.approved)
			return false;
		if (authorities == null) {
			if (other.authorities != null)
				return false;
		}
		else if (!authorities.equals(other.authorities))
			return false;
		if (extensionProperties == null) {
			if (other.extensionProperties != null)
				return false;
		}
		else if (!extensionProperties.equals(other.extensionProperties))
			return false;
		if (redirectUri == null) {
			if (other.redirectUri != null)
				return false;
		}
		else if (!redirectUri.equals(other.redirectUri))
			return false;
		if (resourceIds == null) {
			if (other.resourceIds != null)
				return false;
		}
		else if (!resourceIds.equals(other.resourceIds))
			return false;
		return true;
	}

}
