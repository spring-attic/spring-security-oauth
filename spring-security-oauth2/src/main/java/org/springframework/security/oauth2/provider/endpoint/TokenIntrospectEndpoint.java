/*
 * Copyright 2015 the original author or authors.
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
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultIntrospectionAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller which allows introspection of tokens allowing a resource server to query an  authorization server to determine active state of a token.
 * <p/>
 * Targeted to https://tools.ietf.org/html/draft-ietf-oauth-introspection-08
 *
 * @author Jeff Beck
 */
@FrameworkEndpoint
public class TokenIntrospectEndpoint {

	private ResourceServerTokenServices resourceServerTokenServices;
	private AccessTokenConverter accessTokenConverter = new DefaultIntrospectionAccessTokenConverter();

	protected final Log logger = LogFactory.getLog(getClass());

	public TokenIntrospectEndpoint(ResourceServerTokenServices resourceServerTokenServices) {
		this.resourceServerTokenServices = resourceServerTokenServices;
	}

	/**
	 * @param accessTokenConverter the accessTokenConverter to set
	 */
	public void setAccessTokenConverter(AccessTokenConverter accessTokenConverter) {
		this.accessTokenConverter = accessTokenConverter;
	}

	@RequestMapping(value = "/oauth/introspect")
	@ResponseBody
	public Map<String, ?> introspectToken(@RequestParam("token") String value,
																				@RequestParam(value = "resource_id", required = false) String resourceId,
																				@RequestParam(value = "token_type_hint", required = false) String tokenType) {

		OAuth2AccessToken token = resourceServerTokenServices.readAccessToken(value);
		if (token == null || token.isExpired()) {
			Map<String, Object> response = new HashMap<String, Object>();
			response.put("active",false);
			return response;
		}

		OAuth2Authentication authentication = resourceServerTokenServices.loadAuthentication(token.getValue());

		return accessTokenConverter.convertAccessToken(token, authentication);
	}
}
