package org.springframework.security.oauth2.provider;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

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
	private List<String> scope = Collections.emptyList();
	private List<String> resourceIds = Collections.emptyList();
	private List<String> authorizedGrantTypes = Collections.emptyList();
	private String webServerRedirectUri;
	private List<GrantedAuthority> authorities = Collections.emptyList();

	public BaseClientDetails() {
	}

	public BaseClientDetails(String commaSeparatedResourceIds, String commaSeparatedScopes, String commaSeparatedAuthorizedGrantTypes,
			String commaSeparatedAuthorities) {

		if (StringUtils.hasText(commaSeparatedResourceIds)) {
			List<String> resourceIds = Arrays.asList(StringUtils.commaDelimitedListToStringArray(commaSeparatedResourceIds));
			if (!resourceIds.isEmpty()) {
				this.resourceIds = resourceIds;
			}
		}

		if (StringUtils.hasText(commaSeparatedScopes)) {
			List<String> scopeList = Arrays.asList(StringUtils.commaDelimitedListToStringArray(commaSeparatedScopes));
			if (!scopeList.isEmpty()) {
				this.scope = scopeList;
			}
		}

		if (StringUtils.hasText(commaSeparatedAuthorizedGrantTypes)) {
			this.authorizedGrantTypes = Arrays.asList(StringUtils
					.commaDelimitedListToStringArray(commaSeparatedAuthorizedGrantTypes));
		} else {
			this.authorizedGrantTypes = Arrays.asList("authorization_code", "refresh_token");
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

	public List<String> getScope() {
		return scope;
	}

	public void setScope(List<String> scope) {
		this.scope = scope;
	}

	public List<String> getResourceIds() {
		return resourceIds;
	}

	public void setResourceIds(List<String> resourceIds) {
		this.resourceIds = resourceIds;
	}

	public List<String> getAuthorizedGrantTypes() {
		return authorizedGrantTypes;
	}

	public void setAuthorizedGrantTypes(List<String> authorizedGrantTypes) {
		this.authorizedGrantTypes = authorizedGrantTypes;
	}

	public String getWebServerRedirectUri() {
		return webServerRedirectUri;
	}

	public void setWebServerRedirectUri(String webServerRedirectUri) {
		this.webServerRedirectUri = webServerRedirectUri;
	}

	public List<GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(List<GrantedAuthority> authorities) {
		this.authorities = authorities;
	}
}
