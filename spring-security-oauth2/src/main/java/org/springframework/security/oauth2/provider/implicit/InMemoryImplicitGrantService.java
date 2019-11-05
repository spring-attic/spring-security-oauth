package org.springframework.security.oauth2.provider.implicit;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.TokenRequest;

/**
 * In-memory implementation of the ImplicitGrantService.
 *
 * <p>
 * @deprecated See the <a href="https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide">OAuth 2.0 Migration Guide</a> for Spring Security 5.
 *
 * @author Amanda Anganes
 *
 */
@SuppressWarnings("deprecation")
@Deprecated
public class InMemoryImplicitGrantService implements ImplicitGrantService {

	protected final ConcurrentHashMap<TokenRequest, OAuth2Request> requestStore = new ConcurrentHashMap<TokenRequest, OAuth2Request>();
	
	public void store(OAuth2Request originalRequest, TokenRequest tokenRequest) {
		this.requestStore.put(tokenRequest, originalRequest);
	}

	public OAuth2Request remove(TokenRequest tokenRequest) {
		OAuth2Request request = this.requestStore.remove(tokenRequest);
		return request;
	}

}
