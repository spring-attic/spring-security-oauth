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

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.builders.InMemoryClientDetailsServiceBuilder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.RequestTokenFactory;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * @author Dave Syer
 *
 */
public class TokenServicesWithTokenEnhancerTests {

	private DefaultTokenServices tokenServices = new DefaultTokenServices();

	private JwtAccessTokenConverter jwtTokenEnhancer = new JwtAccessTokenConverter();

	private TokenEnhancerChain enhancer = new TokenEnhancerChain();

	private UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken("bob", "N/A",
			AuthorityUtils.commaSeparatedStringToAuthorityList("ROLE_USER"));

	private OAuth2Request request = RequestTokenFactory.createOAuth2Request("client", true, Arrays.asList("read"));

	private OAuth2Authentication authentication = new OAuth2Authentication(request, user);

	@Before
	public void init() throws Exception {
		tokenServices.setClientDetailsService(new InMemoryClientDetailsServiceBuilder().withClient("client")
				.authorizedGrantTypes("authorization_code").scopes("read").secret("secret").and().build());
		enhancer.setTokenEnhancers(Arrays.<TokenEnhancer> asList(jwtTokenEnhancer));
		jwtTokenEnhancer.afterPropertiesSet();
		tokenServices.setTokenStore(new JwtTokenStore(jwtTokenEnhancer));
		tokenServices.setTokenEnhancer(enhancer);
	}

	@Test
	public void scopePreservedWhenTokenCreated() {
		assertEquals("[read]", tokenServices.createAccessToken(authentication).getScope().toString());
		tokenServices.getAccessToken(authentication);
	}

	@Test
	public void scopePreservedWhenTokenDecoded() {
		OAuth2AccessToken token = tokenServices.createAccessToken(authentication);
		assertEquals("[read]", tokenServices.loadAuthentication(token.getValue()).getOAuth2Request().getScope()
				.toString());
	}

	@Test
	public void customUserPreservedWhenTokenDecoded() {
		DefaultAccessTokenConverter tokenConverter = new DefaultAccessTokenConverter();
		tokenConverter.setUserTokenConverter(new UserAuthenticationConverter() {
			
			@Override
			public Authentication extractAuthentication(Map<String, ?> map) {
				return new FooAuthentication((String) map.get("user"));
			}
			
			@Override
			public Map<String, ?> convertUserAuthentication(Authentication userAuthentication) {
				Map<String, Object> map = new HashMap<String, Object>();
				map.put("user", userAuthentication.getName());
				map.put("foo", "bar");
				return map ;
			}
		});
		jwtTokenEnhancer.setAccessTokenConverter(tokenConverter);
		OAuth2AccessToken token = tokenServices.createAccessToken(authentication);
		assertEquals("bob", tokenServices.loadAuthentication(token.getValue()).getUserAuthentication().getName());
	}

	@Test
	public void additionalInfoPreservedWhenTokenDecoded() {
		TokenEnhancer info = new TokenEnhancer() {
			@Override
			public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
				DefaultOAuth2AccessToken result = new DefaultOAuth2AccessToken(accessToken);
				result.getAdditionalInformation().put("foo", "bar");
				return result;
			}
		};
		enhancer.setTokenEnhancers(Arrays.<TokenEnhancer> asList(info , jwtTokenEnhancer));
		OAuth2AccessToken token = tokenServices.createAccessToken(authentication);
		assertEquals("bar", token.getAdditionalInformation().get("foo"));
		assertEquals("bar", tokenServices.readAccessToken(token.getValue()).getAdditionalInformation().get("foo"));
	}
	
	@SuppressWarnings("serial")
	protected static class FooAuthentication extends AbstractAuthenticationToken {

		private String name;

		public FooAuthentication(String name) {
			super(AuthorityUtils.commaSeparatedStringToAuthorityList("USER"));
			this.name = name;
		}

		@Override
		public Object getCredentials() {
			return "N/A";
		}

		@Override
		public Object getPrincipal() {
			return name;
		}
		
	}

}
