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

package org.springframework.security.oauth2.config.xml;

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
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
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
		String type = element.getAttribute("type");
		if ("authorization_code".equals(type)) {
			return AuthorizationCodeResourceDetails.class;
		}
		if ("implicit".equals(type)) {
			return ImplicitResourceDetails.class;
		}
		if ("client_credentials".equals(type)) {
			return ClientCredentialsResourceDetails.class;
		}
		if ("password".equals(type)) {
			return ResourceOwnerPasswordResourceDetails.class;
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
		if (!StringUtils.hasText(type)) {
			type = "client_credentials";
		}
		builder.addPropertyValue("grantType", type);

		String accessTokenUri = element.getAttribute("access-token-uri");
		if (!StringUtils.hasText(accessTokenUri) && !"implicit".equals(type)) {
			parserContext.getReaderContext()
					.error("An accessTokenUri must be supplied on a resource element of type " + type, element);
		}
		builder.addPropertyValue("accessTokenUri", accessTokenUri);

		String clientId = element.getAttribute("client-id");
		if (!StringUtils.hasText(clientId)) {
			parserContext.getReaderContext().error("An clientId must be supplied on a resource element", element);
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
			if (needsUserAuthorizationUri(type)) {
				builder.addPropertyValue("userAuthorizationUri", userAuthorizationUri);
			} else {
				parserContext.getReaderContext().error("The " + type + " grant type does not accept an authorization URI", element);
			}
		} else {
			if (needsUserAuthorizationUri(type)) {
				parserContext.getReaderContext().error("An authorization URI must be supplied for a resource of type " + type, element);
			}
		}

		String preEstablishedRedirectUri = element.getAttribute("pre-established-redirect-uri");
		if (StringUtils.hasText(preEstablishedRedirectUri)) {
			builder.addPropertyValue("preEstablishedRedirectUri", preEstablishedRedirectUri);
		}

		String requireImmediateAuthorization = element.getAttribute("require-immediate-authorization");
		if (StringUtils.hasText(requireImmediateAuthorization)) {
			builder.addPropertyValue("requireImmediateAuthorization", requireImmediateAuthorization);
		}

		String useCurrentUri = element.getAttribute("use-current-uri");
		if (StringUtils.hasText(useCurrentUri)) {
			builder.addPropertyValue("useCurrentUri", useCurrentUri);
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
			bearerTokenName = OAuth2AccessToken.ACCESS_TOKEN;
		}
		builder.addPropertyValue("tokenName", bearerTokenName);

		if (type.equals("password")) {
			String[] attributeNames = {"username", "password"};
			for (String attributeName : attributeNames) {
				String attribute = element.getAttribute(attributeName);
				if (StringUtils.hasText(attribute)) {
					builder.addPropertyValue(attributeName, attribute);
				} else {
					parserContext.getReaderContext().error("A " + attributeName + " must be supplied on a resource element of type " + type, element);
				}
			}
		}
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

	private boolean needsUserAuthorizationUri(String type) {
		return type.equals("authorization_code") || type.equals("implicit");
	}

}