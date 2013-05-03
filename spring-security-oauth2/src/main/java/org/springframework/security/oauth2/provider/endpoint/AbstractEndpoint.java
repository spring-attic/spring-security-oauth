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


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.provider.OAuth2RequestManager;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.DefaultOAuth2RequestManager;
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

	private OAuth2RequestManager oAuth2RequestManager;

	private OAuth2RequestManager defaultOAuth2RequestManager;

	public void afterPropertiesSet() throws Exception {
		Assert.state(tokenGranter != null, "TokenGranter must be provided");
		Assert.state(clientDetailsService != null, "ClientDetailsService must be provided");
		defaultOAuth2RequestManager = new DefaultOAuth2RequestManager(getClientDetailsService());
		if (oAuth2RequestManager == null) {
			oAuth2RequestManager = defaultOAuth2RequestManager;
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

	protected OAuth2RequestManager getOAuth2RequestManager() {
		return oAuth2RequestManager;
	}

	protected OAuth2RequestManager getDefaultOAuth2RequestManager() {
		return defaultOAuth2RequestManager;
	}

	public void setOAuth2RequestManager(OAuth2RequestManager oAuth2RequestManager) {
		this.oAuth2RequestManager = oAuth2RequestManager;
	}

	protected ClientDetailsService getClientDetailsService() {
		return clientDetailsService;
	}

	public void setClientDetailsService(ClientDetailsService clientDetailsService) {
		this.clientDetailsService = clientDetailsService;
	}

}