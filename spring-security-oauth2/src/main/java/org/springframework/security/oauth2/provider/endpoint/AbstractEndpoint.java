/*
 * Copyright 2002-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.provider.endpoint;

import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.common.exceptions.InvalidScopeException;
import org.springframework.security.oauth2.provider.AuthorizationRequestFactory;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequestFactory;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.util.Assert;

/**
 * @author Dave Syer
 * 
 */
public class AbstractEndpoint implements InitializingBean {

	protected final Log logger = LogFactory.getLog(getClass());

	private WebResponseExceptionTranslator providerExceptionHandler = new DefaultWebResponseExceptionTranslator();

	private TokenGranter tokenGranter;

	private ClientDetailsService clientDetailsService;

	private AuthorizationRequestFactory authorizationRequestFactory;

	public void afterPropertiesSet() throws Exception {
		Assert.state(tokenGranter != null, "TokenGranter must be provided");
		Assert.state(getClientDetailsService() != null, "ClientDetailsService must be provided");
		if (authorizationRequestFactory == null) {
			authorizationRequestFactory = new DefaultAuthorizationRequestFactory(getClientDetailsService());
		}
	}

	public void setProviderExceptionHandler(WebResponseExceptionTranslator providerExceptionHandler) {
		this.providerExceptionHandler = providerExceptionHandler;
	}

	public void setTokenGranter(TokenGranter tokenGranter) {
		this.tokenGranter = tokenGranter;
	}
	
	protected TokenGranter getTokenGranter() {
		return tokenGranter;
	}
	
	protected WebResponseExceptionTranslator getExceptionTranslator() {
		return providerExceptionHandler;
	}

	protected AuthorizationRequestFactory getAuthorizationRequestFactory() {
		return authorizationRequestFactory;
	}

	public void setAuthorizationRequestFactory(AuthorizationRequestFactory authorizationRequestFactory) {
		this.authorizationRequestFactory = authorizationRequestFactory;
	}

	protected ClientDetailsService getClientDetailsService() {
		return clientDetailsService;
	}

	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

	protected void validateScope(Set<String> scopes, String clientId) {
		ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
		if (clientDetails.isScoped()) {
			Set<String> validScope = clientDetails.getScope();
			for (String scope : scopes) {
				if (!validScope.contains(scope)) {
					throw new InvalidScopeException("Invalid scope: " + scope, validScope);
				}
			}
		}
	}

}