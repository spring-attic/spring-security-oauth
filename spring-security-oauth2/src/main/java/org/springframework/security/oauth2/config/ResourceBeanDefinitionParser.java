/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.TypedStringValue;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.AbstractSingleBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * @author Ryan Heaton
 */
public class ResourceBeanDefinitionParser extends AbstractSingleBeanDefinitionParser {

	@Override
	protected Class<?> getBeanClass(Element element) {
		if ("authorization_code".equals(element.getAttribute("type"))) {
			return AuthorizationCodeResourceDetails.class;
		}
		if ("client_credentials".equals(element.getAttribute("type"))) {
			return ClientCredentialsResourceDetails.class;
		}
		return BaseOAuth2ProtectedResourceDetails.class;
	}

	@Override
	protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
		String id = element.getAttribute("id");
		if (!StringUtils.hasText(id)) {
			parserContext.getReaderContext().error("An id must be supplied on a resource element.", element);
		}
		builder.addPropertyValue("id", id);

		String type = element.getAttribute("type");
		if (StringUtils.hasText(type)) {
			builder.addPropertyValue("grantType", type);
		}

		String accessTokenUri = element.getAttribute("access-token-uri");
		if (!StringUtils.hasText(accessTokenUri)) {
			parserContext.getReaderContext()
					.error("An accessTokenUri must be supplied on a resource element.", element);
		}
		builder.addPropertyValue("accessTokenUri", accessTokenUri);

		String clientId = element.getAttribute("client-id");
		if (!StringUtils.hasText(clientId)) {
			parserContext.getReaderContext().error("An clientId must be supplied on a resource element.", element);
		}
		builder.addPropertyValue("clientId", clientId);

		String clientSecret = element.getAttribute("client-secret");
		if (StringUtils.hasText(clientSecret)) {
			builder.addPropertyValue("clientSecret", clientSecret);
		}

		String clientAuthenticationScheme = element.getAttribute("client-authentication-scheme");
		if (StringUtils.hasText(clientAuthenticationScheme)) {
			builder.addPropertyValue("clientAuthenticationScheme", clientAuthenticationScheme);
		}

		String userAuthorizationUri = element.getAttribute("user-authorization-uri");
		if (StringUtils.hasText(userAuthorizationUri)) {
			if (type.equals("client_credentials")) {
				parserContext.getReaderContext().error("The client_credentials grant type does not accept an authorization URI", element);
			} else {
				builder.addPropertyValue("userAuthorizationUri", userAuthorizationUri);
			}
		}

		String preEstablishedRedirectUri = element.getAttribute("preEstablished-redirect-uri");
		if (StringUtils.hasText(preEstablishedRedirectUri)) {
			builder.addPropertyValue("preEstablishedRedirectUri", preEstablishedRedirectUri);
		}

		String requireImmediateAuthorization = element.getAttribute("require-immediate-authorization");
		if (StringUtils.hasText(requireImmediateAuthorization)) {
			builder.addPropertyValue("requireImmediateAuthorization", requireImmediateAuthorization);
		}

		String scope = element.getAttribute("scope");
		if (StringUtils.hasText(scope)) {
			BeanDefinitionBuilder scopesBuilder = BeanDefinitionBuilder
					.genericBeanDefinition(StringListFactoryBean.class);
			scopesBuilder.addConstructorArgValue(new TypedStringValue(scope));
			builder.addPropertyValue("scope", scopesBuilder.getBeanDefinition());
		}

		AuthenticationScheme btm = AuthenticationScheme.header;
		String bearerTokenMethod = element.getAttribute("authentication-scheme");
		if (StringUtils.hasText(bearerTokenMethod)) {
			btm = AuthenticationScheme.valueOf(bearerTokenMethod);
		}
		builder.addPropertyValue("authenticationScheme", btm);

		String bearerTokenName = element.getAttribute("token-name");
		if (!StringUtils.hasText(bearerTokenName)) {
			bearerTokenName = OAuth2AccessToken.BEARER_TYPE_PARAMETER;
		}
		builder.addPropertyValue("tokenName", bearerTokenName);

	}

	/**
	 * Convenience factory bean for enabling comma-separated lists to be specified either as literals or externalized as
	 * expressions or placeholders. N.B. this would not be necessary if Spring used its ConversionService by default
	 * (users have to register one).
	 */
	public static class StringListFactoryBean implements FactoryBean<List<String>> {

		private final String commaSeparatedList;

		public StringListFactoryBean(String commaSeparatedList) {
			this.commaSeparatedList = commaSeparatedList;
		}

		public List<String> getObject() throws Exception {
			return new ArrayList<String>(Arrays.asList(StringUtils.commaDelimitedListToStringArray(commaSeparatedList)));
		}

		public Class<?> getObjectType() {
			return List.class;
		}

		public boolean isSingleton() {
			return true;
		}

	}

}