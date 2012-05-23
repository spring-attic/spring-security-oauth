/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.springframework.security.oauth2.config;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.oauth2.client.context.OAuth2ClientContext;
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
