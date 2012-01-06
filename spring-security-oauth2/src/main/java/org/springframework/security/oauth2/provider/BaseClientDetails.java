package org.springframework.security.oauth2.provider;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.StringUtils;

/**
 * Base implementation of {@link org.springframework.security.oauth2.provider.ClientDetails}.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class BaseClientDetails implements ClientDetails {

	private String clientId;

	private String clientSecret;

	private Set<String> scope = Collections.emptySet();

	private Set<String> resourceIds = Collections.emptySet();

	private Set<String> authorizedGrantTypes = Collections.emptySet();

	private String registeredRedirectUri;

	private List<GrantedAuthority> authorities = Collections.emptyList();

	public BaseClientDetails() {
	}

	public BaseClientDetails(String commaSeparatedResourceIds, String commaSeparatedScopes,
			String commaSeparatedAuthorizedGrantTypes, String commaSeparatedAuthorities) {

		if (StringUtils.hasText(commaSeparatedResourceIds)) {
			Set<String> resourceIds = StringUtils.commaDelimitedListToSet(commaSeparatedResourceIds);
			if (!resourceIds.isEmpty()) {
				this.resourceIds = resourceIds;
			}
		}

		if (StringUtils.hasText(commaSeparatedScopes)) {
			Set<String> scopeList = StringUtils.commaDelimitedListToSet(commaSeparatedScopes);
			if (!scopeList.isEmpty()) {
				this.scope = scopeList;
			}
		}

		if (StringUtils.hasText(commaSeparatedAuthorizedGrantTypes)) {
			this.authorizedGrantTypes = StringUtils.commaDelimitedListToSet(commaSeparatedAuthorizedGrantTypes);
		}
		else {
			this.authorizedGrantTypes = new HashSet<String>(Arrays.asList("authorization_code", "refresh_token"));
		}

		if (StringUtils.hasText(commaSeparatedAuthorities)) {
			this.authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(commaSeparatedAuthorities);
		}
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public boolean isSecretRequired() {
		return this.clientSecret != null;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public boolean isScoped() {
		return this.scope != null && !this.scope.isEmpty();
	}

	public Set<String> getScope() {
		return scope;
	}

	public void setScope(Collection<String> scope) {
		this.scope = new LinkedHashSet<String>(scope);
	}

	public Set<String> getResourceIds() {
		return resourceIds;
	}

	public void setResourceIds(Collection<String> resourceIds) {
		this.resourceIds = new LinkedHashSet<String>(resourceIds);
	}

	public Set<String> getAuthorizedGrantTypes() {
		return authorizedGrantTypes;
	}

	public void setAuthorizedGrantTypes(Collection<String> authorizedGrantTypes) {
		this.authorizedGrantTypes = new LinkedHashSet<String>(authorizedGrantTypes);
	}

	public String getRegisteredRedirectUri() {
		return registeredRedirectUri;
	}

	public void setRegisteredRedirectUri(String registeredRedirectUri) {
		this.registeredRedirectUri = registeredRedirectUri;
	}

	public Collection<GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(Collection<GrantedAuthority> authorities) {
		this.authorities = new ArrayList<GrantedAuthority>(authorities);
	}
}
