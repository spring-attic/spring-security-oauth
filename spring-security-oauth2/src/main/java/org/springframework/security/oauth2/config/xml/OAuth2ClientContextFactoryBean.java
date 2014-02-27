/*
 * Copyright 2006-2011 the original author or authors.
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


package org.springframework.security.oauth2.config.xml;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;

/**
 * Convenience factory for OAuth2ClientContext that is aware of the need for a different context if the resource is for a
 * client credentials grant. Client credentials grants will always have the same credentials for all requests, so
 * there's no point protecting the context with session and request scopes.
 * 
 * @author Dave Syer
 * 
 */
public class OAuth2ClientContextFactoryBean implements FactoryBean<OAuth2ClientContext> {

	private OAuth2ProtectedResourceDetails resource;

	private OAuth2ClientContext bareContext;

	private OAuth2ClientContext scopedContext;
	
	/**
	 * @param resource the resource to set
	 */
	public void setResource(OAuth2ProtectedResourceDetails resource) {
		this.resource = resource;
	}

	/**
	 * @param scopedContext the scopedContext to set
	 */
	public void setScopedContext(OAuth2ClientContext scopedContext) {
		this.scopedContext = scopedContext;
	}

	/**
	 * @param bareContext the bareContext to set
	 */
	public void setBareContext(OAuth2ClientContext bareContext) {
		this.bareContext = bareContext;
	}

	public OAuth2ClientContext getObject() throws Exception {
		if (resource instanceof ClientCredentialsResourceDetails) {
			return bareContext;
		}
		return scopedContext;
	}

	public Class<?> getObjectType() {
		return OAuth2ClientContext.class;
	}

	public boolean isSingleton() {
		return true;
	}

}
