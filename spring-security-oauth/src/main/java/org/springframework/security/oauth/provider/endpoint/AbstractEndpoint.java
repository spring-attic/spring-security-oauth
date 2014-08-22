/*
 * Copyright 2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.oauth.provider.endpoint;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.util.Assert;

/**
 * Base class for framework end points.
 *
 * @author <a rel="author" href="http://autayeu.com/">Aliaksandr Autayeu</a>
 */
public abstract class AbstractEndpoint implements InitializingBean, MessageSourceAware {

	protected final Log logger = LogFactory.getLog(getClass());

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	// The OAuth spec doesn't specify a content-type of the response.  However, it's NOT
	// "application/x-www-form-urlencoded" because the response isn't URL-encoded. Until
	// something is specified, we'll assume that it's just "text/plain".
	protected String responseContentType = "text/plain;charset=utf-8";

	private boolean require10a = true;
	private OAuthProviderTokenServices tokenServices;

	public void afterPropertiesSet() throws Exception {
		Assert.notNull(tokenServices, "Token services are required.");
	}

	/**
	 * Whether to require 1.0a support.
	 *
	 * @return Whether to require 1.0a support.
	 */
	public boolean isRequire10a() {
		return require10a;
	}

	/**
	 * Whether to require 1.0a support.
	 *
	 * @param require10a Whether to require 1.0a support.
	 */
	public void setRequire10a(boolean require10a) {
		this.require10a = require10a;
	}

	/**
	 * Set the message source.
	 *
	 * @param messageSource The message source.
	 */
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	/**
	 * Get the OAuth token services.
	 *
	 * @return The OAuth token services.
	 */
	public OAuthProviderTokenServices getTokenServices() {
		return tokenServices;
	}

	/**
	 * The OAuth token services.
	 *
	 * @param tokenServices The OAuth token services.
	 */
	@Autowired
	public void setTokenServices(OAuthProviderTokenServices tokenServices) {
		this.tokenServices = tokenServices;
	}

	/**
	 * The content type of the response.
	 *
	 * @return The content type of the response.
	 */
	public String getResponseContentType() {
		return responseContentType;
	}

	/**
	 * The content type of the response.
	 *
	 * @param responseContentType The content type of the response.
	 */
	public void setResponseContentType(String responseContentType) {
		this.responseContentType = responseContentType;
	}
}