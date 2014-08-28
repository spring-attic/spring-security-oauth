/*
 * Copyright 2013-2014 the original author or authors.
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

package org.springframework.security.oauth2.provider.token;

import static org.junit.Assert.*;

import java.util.Collections;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;

/**
 * @author Dave Syer
 *
 */
public class DefaultAccessTokenConverterTests {

	private DefaultAccessTokenConverter converter = new DefaultAccessTokenConverter();

	private UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken("foo",
			"bar", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

	private OAuth2Authentication authentication;

	@Before
	public void init() {
		OAuth2Request request = RequestTokenFactory.createOAuth2Request(null, "id",
				AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_CLIENT"), true, Collections.singleton("read"),
				Collections.singleton("resource"), null, null, null);
		authentication = new OAuth2Authentication(request, userAuthentication);
	}

	@Test
	public void extractAuthentication() {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken("FOO");
		Map<String, ?> map = converter.convertAccessToken(token, authentication);
		assertTrue(map.containsKey(AccessTokenConverter.AUD));
		OAuth2Authentication extracted = converter.extractAuthentication(map);
		assertTrue(extracted.getOAuth2Request().getResourceIds().contains("resource"));
	}

}
