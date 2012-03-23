package org.springframework.security.oauth2.provider;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.annotate.JsonIgnoreProperties;
import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.codehaus.jackson.map.annotate.JsonSerialize.Inclusion;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.StringUtils;

/**
 * Base implementation of {@link org.springframework.security.oauth2.provider.ClientDetails}.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
@JsonSerialize(include = Inclusion.NON_DEFAULT)
@JsonIgnoreProperties(ignoreUnknown = true)
public class BaseClientDetails implements ClientDetails {

	@JsonProperty("client_id")
	private String clientId;

	@JsonProperty("client_sceret")
	private String clientSecret;

	private Set<String> scope = Collections.emptySet();

	@JsonProperty("resource_ids")
	private Set<String> resourceIds = Collections.emptySet();

	@JsonProperty("authorized_grant_types")
	private Set<String> authorizedGrantTypes = Collections.emptySet();

	@JsonProperty("redirect_uri")
	private Set<String> registeredRedirectUris;

	private List<GrantedAuthority> authorities = Collections.emptyList();

	@JsonProperty("access_token_validity")
	private int accessTokenValiditySeconds = 0;

	public BaseClientDetails() {
	}

	public BaseClientDetails(String resourceIds, String scopes, String grantTypes, String authorities) {
		this(resourceIds, scopes, grantTypes, authorities, null);
	}

	public BaseClientDetails(String resourceIds, String scopes, String grantTypes, String authorities,
			String redirectUris) {

		if (StringUtils.hasText(resourceIds)) {
			Set<String> resources = StringUtils.commaDelimitedListToSet(resourceIds);
			if (!resources.isEmpty()) {
				this.resourceIds = resources;
			}
		}

		if (StringUtils.hasText(scopes)) {
			Set<String> scopeList = StringUtils.commaDelimitedListToSet(scopes);
			if (!scopeList.isEmpty()) {
				this.scope = scopeList;
			}
		}

		if (StringUtils.hasText(grantTypes)) {
			this.authorizedGrantTypes = StringUtils.commaDelimitedListToSet(grantTypes);
		}
		else {
			this.authorizedGrantTypes = new HashSet<String>(Arrays.asList("authorization_code", "refresh_token"));
		}

		if (StringUtils.hasText(authorities)) {
			this.authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(authorities);
		}

		if (StringUtils.hasText(redirectUris)) {
			this.registeredRedirectUris = StringUtils.commaDelimitedListToSet(redirectUris);
		}
	}

	@JsonIgnore
	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	@JsonIgnore
	public boolean isSecretRequired() {
		return this.clientSecret != null;
	}

	@JsonIgnore
	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	@JsonIgnore
	public boolean isScoped() {
		return this.scope != null && !this.scope.isEmpty();
	}

	public Set<String> getScope() {
		return scope;
	}

	public void setScope(Collection<String> scope) {
		this.scope = new LinkedHashSet<String>(scope);
	}

	@JsonIgnore
	public Set<String> getResourceIds() {
		return resourceIds;
	}

	public void setResourceIds(Collection<String> resourceIds) {
		this.resourceIds = new LinkedHashSet<String>(resourceIds);
	}

	@JsonIgnore
	public Set<String> getAuthorizedGrantTypes() {
		return authorizedGrantTypes;
	}

	public void setAuthorizedGrantTypes(Collection<String> authorizedGrantTypes) {
		this.authorizedGrantTypes = new LinkedHashSet<String>(authorizedGrantTypes);
	}

	@JsonIgnore
	public Set<String> getRegisteredRedirectUri() {
		return registeredRedirectUris;
	}

	public void setRegisteredRedirectUri(Set<String> registeredRedirectUris) {
		this.registeredRedirectUris = registeredRedirectUris;
	}

	@SuppressWarnings("unused")
	@JsonProperty("authorities")
	private Collection<String> getAuthoritiesAsStrings() {
		return AuthorityUtils.authorityListToSet(authorities);
	}

	@SuppressWarnings("unused")
	@JsonProperty("authorities")
	private void setAuthoritiesAsStrings(List<String> roles) {
		this.authorities = AuthorityUtils.createAuthorityList(roles.toArray(new String[roles.size()]));
	}

	@JsonIgnore
	public Collection<GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(Collection<GrantedAuthority> authorities) {
		this.authorities = new ArrayList<GrantedAuthority>(authorities);
	}

	@JsonIgnore
	public int getAccessTokenValiditySeconds() {
		return accessTokenValiditySeconds;
	}

	public void setAccessTokenValiditySeconds(int accessTokenValiditySeconds) {
		this.accessTokenValiditySeconds = accessTokenValiditySeconds;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + accessTokenValiditySeconds;
		result = prime * result + ((authorities == null) ? 0 : authorities.hashCode());
		result = prime * result + ((authorizedGrantTypes == null) ? 0 : authorizedGrantTypes.hashCode());
		result = prime * result + ((clientId == null) ? 0 : clientId.hashCode());
		result = prime * result + ((clientSecret == null) ? 0 : clientSecret.hashCode());
		result = prime * result + ((registeredRedirectUris == null) ? 0 : registeredRedirectUris.hashCode());
		result = prime * result + ((resourceIds == null) ? 0 : resourceIds.hashCode());
		result = prime * result + ((scope == null) ? 0 : scope.hashCode());
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
		BaseClientDetails other = (BaseClientDetails) obj;
		if (accessTokenValiditySeconds != other.accessTokenValiditySeconds)
			return false;
		if (authorities == null) {
			if (other.authorities != null)
				return false;
		}
		else if (!authorities.equals(other.authorities))
			return false;
		if (authorizedGrantTypes == null) {
			if (other.authorizedGrantTypes != null)
				return false;
		}
		else if (!authorizedGrantTypes.equals(other.authorizedGrantTypes))
			return false;
		if (clientId == null) {
			if (other.clientId != null)
				return false;
		}
		else if (!clientId.equals(other.clientId))
			return false;
		if (clientSecret == null) {
			if (other.clientSecret != null)
				return false;
		}
		else if (!clientSecret.equals(other.clientSecret))
			return false;
		if (registeredRedirectUris == null) {
			if (other.registeredRedirectUris != null)
				return false;
		}
		else if (!registeredRedirectUris.equals(other.registeredRedirectUris))
			return false;
		if (resourceIds == null) {
			if (other.resourceIds != null)
				return false;
		}
		else if (!resourceIds.equals(other.resourceIds))
			return false;
		if (scope == null) {
			if (other.scope != null)
				return false;
		}
		else if (!scope.equals(other.scope))
			return false;
		return true;
	}

}
