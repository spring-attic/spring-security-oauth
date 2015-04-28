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
package org.springframework.security.oauth2.provider.token;

import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Map;

/**
 * Implementation of {@link AccessTokenConverter} that extends the default converter adding properties from the introspection spec.
 * <p/>
 * See https://tools.ietf.org/html/draft-ietf-oauth-introspection-08
 *
 * @author Jeff Beck
 */
public class DefaultIntrospectionAccessTokenConverter extends DefaultAccessTokenConverter {

	@Override
	public Map<String, ?> convertAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		Map<String, Object> response = (Map<String, Object>)super.convertAccessToken(token, authentication);

		response.put("active", !token.isExpired());

		return response;
	}
}
