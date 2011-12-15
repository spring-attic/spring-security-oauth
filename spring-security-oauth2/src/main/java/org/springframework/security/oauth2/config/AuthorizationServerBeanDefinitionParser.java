/*
 * Copyright 2008-2009 Web Cohesion
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

package org.springframework.security.oauth2.config;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.BeanIds;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeTokenGranter;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.filter.EndpointValidationFilter;
import org.springframework.security.oauth2.provider.implicit.ImplicitTokenGranter;
import org.springframework.security.oauth2.provider.password.ResourceOwnerPasswordTokenGranter;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Parser for the OAuth "provider" element.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class AuthorizationServerBeanDefinitionParser extends ProviderBeanDefinitionParser {

	@Override
	protected AbstractBeanDefinition parseEndpointAndReturnFilter(Element element, ParserContext parserContext,
			String tokenServicesRef, String serializerRef) {

		String clientDetailsRef = element.getAttribute("client-details-service-ref");
		String passwordEncoderRef = element.getAttribute("password-encoder-ref");
		String tokenEndpointUrl = element.getAttribute("token-endpoint-url");
		String authorizationEndpointUrl = element.getAttribute("authorization-endpoint-url");
		String tokenGranterRef = element.getAttribute("token-granter-ref");
		String redirectStrategyRef = element.getAttribute("redirect-strategy-ref");

		if (!StringUtils.hasText(clientDetailsRef)) {
			parserContext.getReaderContext().error("A client details service is mandatory", element);
		}

		if (StringUtils.hasText(tokenEndpointUrl) || StringUtils.hasText(authorizationEndpointUrl)) {
			BeanDefinitionBuilder endpointValidationFilterBean = BeanDefinitionBuilder
					.rootBeanDefinition(EndpointValidationFilter.class);
			if (StringUtils.hasText(tokenEndpointUrl)) {
				endpointValidationFilterBean.addPropertyValue("tokenEndpointUrl", tokenEndpointUrl);
			}
			if (StringUtils.hasText(authorizationEndpointUrl)) {
				endpointValidationFilterBean.addPropertyValue("authorizationEndpointUrl", authorizationEndpointUrl);
			}
			// User has to set up a filter in web.xml to pick this up by bean name
			parserContext.getRegistry().registerBeanDefinition("oauth2EndpointUrlFilter",
					endpointValidationFilterBean.getBeanDefinition());
		}

		ManagedList<BeanMetadataElement> tokenGranters = null;
		if (!StringUtils.hasText(tokenGranterRef)) {
			tokenGranterRef = "oauth2TokenGranter";
			BeanDefinitionBuilder tokenGranterBean = BeanDefinitionBuilder
					.rootBeanDefinition(CompositeTokenGranter.class);
			parserContext.getRegistry().registerBeanDefinition(tokenGranterRef, tokenGranterBean.getBeanDefinition());
			tokenGranters = new ManagedList<BeanMetadataElement>();
			tokenGranterBean.addConstructorArgValue(tokenGranters);
		}

		Element authorizationCodeElement = DomUtils.getChildElementByTagName(element, "authorization-code");
		if (authorizationCodeElement != null
				&& !"true".equalsIgnoreCase(authorizationCodeElement.getAttribute("disabled"))) {
			// authorization code grant configuration.
			String approvalPage = authorizationCodeElement.getAttribute("user-approval-page");
			String approvalHandlerRef = authorizationCodeElement.getAttribute("approval-handler-ref");
			String approvalParameter = authorizationCodeElement.getAttribute("approval-parameter-name");
			String authorizationCodeServices = authorizationCodeElement.getAttribute("services-ref");
			String redirectResolverRef = authorizationCodeElement.getAttribute("redirect-resolver-ref");
			String clientTokenCacheRef = authorizationCodeElement.getAttribute("client-token-cache-ref");
			String authorizationCodeRedirectStrategyRef = authorizationCodeElement
					.getAttribute("redirect-strategy-ref");
			if (!StringUtils.hasText(authorizationCodeRedirectStrategyRef)) {
				authorizationCodeRedirectStrategyRef = redirectStrategyRef;
			}

			BeanDefinitionBuilder authorizationEndpointBean = BeanDefinitionBuilder
					.rootBeanDefinition(AuthorizationEndpoint.class);
			BeanDefinitionBuilder authorizationCodeTokenGranterBean = BeanDefinitionBuilder
					.rootBeanDefinition(AuthorizationCodeTokenGranter.class);

			if (StringUtils.hasText(tokenServicesRef)) {
				authorizationCodeTokenGranterBean.addConstructorArgReference(tokenServicesRef);
			}

			if (!StringUtils.hasText(approvalParameter)) {
				// TODO: allow customization of approval parameter
				// authorizationEndpointBean.addPropertyValue("approvalParameter", approvalParameter);
			}

			if (!StringUtils.hasText(authorizationCodeServices)) {
				authorizationCodeServices = "oauth2AuthorizationCodeServices";
				BeanDefinitionBuilder authorizationCodeServicesBean = BeanDefinitionBuilder
						.rootBeanDefinition(InMemoryAuthorizationCodeServices.class);
				parserContext.getRegistry().registerBeanDefinition(authorizationCodeServices,
						authorizationCodeServicesBean.getBeanDefinition());
			}

			authorizationEndpointBean.addPropertyReference("authorizationCodeServices", authorizationCodeServices);
			authorizationCodeTokenGranterBean.addConstructorArgReference(authorizationCodeServices);
			authorizationEndpointBean.addPropertyReference("clientDetailsService", clientDetailsRef);
			authorizationCodeTokenGranterBean.addConstructorArgReference(clientDetailsRef);
			if (StringUtils.hasText(clientTokenCacheRef)) {
				authorizationEndpointBean.addPropertyReference("clientTokenCache", clientTokenCacheRef);
			}
			if (StringUtils.hasText(redirectResolverRef)) {
				authorizationEndpointBean.addPropertyReference("redirectResolver", redirectResolverRef);
			}
			if (StringUtils.hasText(authorizationCodeRedirectStrategyRef)) {
				authorizationEndpointBean
						.addPropertyReference("redirectStrategy", authorizationCodeRedirectStrategyRef);
			}
			if (StringUtils.hasText(approvalPage)) {
				authorizationEndpointBean.addPropertyValue("userApprovalPage", approvalPage);
			}
			if (StringUtils.hasText(approvalHandlerRef)) {
				authorizationEndpointBean.addPropertyReference("userApprovalHandler", approvalHandlerRef);
			}

			parserContext.getRegistry().registerBeanDefinition("oauth2AuthorizationEndpoint",
					authorizationEndpointBean.getBeanDefinition());
			authorizationEndpointBean.addPropertyReference("tokenGranter", tokenGranterRef);
			if (StringUtils.hasText(passwordEncoderRef)) {
				authorizationCodeTokenGranterBean.addPropertyReference("passwordEncoder", passwordEncoderRef);
			}

			if (tokenGranters!=null) {
				tokenGranters.add(authorizationCodeTokenGranterBean.getBeanDefinition());
			}
			// end authorization code provider configuration.
		}

		if (tokenGranters != null) {
			Element refreshTokenElement = DomUtils.getChildElementByTagName(element, "refresh-token");
			if (refreshTokenElement != null && !"true".equalsIgnoreCase(refreshTokenElement.getAttribute("disabled"))) {
				BeanDefinitionBuilder refreshTokenGranterBean = BeanDefinitionBuilder
						.rootBeanDefinition(RefreshTokenGranter.class);
				refreshTokenGranterBean.addConstructorArgReference(tokenServicesRef);
				refreshTokenGranterBean.addConstructorArgReference(clientDetailsRef);
				if (StringUtils.hasText(passwordEncoderRef)) {
					refreshTokenGranterBean.addPropertyReference("passwordEncoder", passwordEncoderRef);
				}
				tokenGranters.add(refreshTokenGranterBean.getBeanDefinition());
			}
			Element implicitElement = DomUtils.getChildElementByTagName(element, "implicit");
			if (implicitElement != null && !"true".equalsIgnoreCase(implicitElement.getAttribute("disabled"))) {
				BeanDefinitionBuilder implicitGranterBean = BeanDefinitionBuilder
						.rootBeanDefinition(ImplicitTokenGranter.class);
				implicitGranterBean.addConstructorArgReference(tokenServicesRef);
				implicitGranterBean.addConstructorArgReference(clientDetailsRef);
				if (StringUtils.hasText(passwordEncoderRef)) {
					implicitGranterBean.addPropertyReference("passwordEncoder", passwordEncoderRef);
				}
				tokenGranters.add(implicitGranterBean.getBeanDefinition());
			}
			Element clientCredentialsElement = DomUtils.getChildElementByTagName(element, "client-credentials");
			if (clientCredentialsElement != null
					&& !"true".equalsIgnoreCase(clientCredentialsElement.getAttribute("disabled"))) {
				BeanDefinitionBuilder clientCredentialsGranterBean = BeanDefinitionBuilder
						.rootBeanDefinition(ClientCredentialsTokenGranter.class);
				clientCredentialsGranterBean.addConstructorArgReference(tokenServicesRef);
				clientCredentialsGranterBean.addConstructorArgReference(clientDetailsRef);
				if (StringUtils.hasText(passwordEncoderRef)) {
					clientCredentialsGranterBean.addPropertyReference("passwordEncoder", passwordEncoderRef);
				}
				tokenGranters.add(clientCredentialsGranterBean.getBeanDefinition());
			}
			Element clientPasswordElement = DomUtils.getChildElementByTagName(element, "password");
			if (clientPasswordElement != null
					&& !"true".equalsIgnoreCase(clientPasswordElement.getAttribute("disabled"))) {
				BeanDefinitionBuilder clientPasswordTokenGranter = BeanDefinitionBuilder
						.rootBeanDefinition(ResourceOwnerPasswordTokenGranter.class);
				String authenticationManagerRef = clientPasswordElement.getAttribute("authentication-manager-ref");
				if (!StringUtils.hasText(authenticationManagerRef)) {
					authenticationManagerRef = BeanIds.AUTHENTICATION_MANAGER;
				}
				clientPasswordTokenGranter.addConstructorArgReference(authenticationManagerRef);
				clientPasswordTokenGranter.addConstructorArgReference(tokenServicesRef);
				clientPasswordTokenGranter.addConstructorArgReference(clientDetailsRef);
				if (StringUtils.hasText(passwordEncoderRef)) {
					clientPasswordTokenGranter.addPropertyReference("passwordEncoder", passwordEncoderRef);
				}
				tokenGranters.add(clientPasswordTokenGranter.getBeanDefinition());
			}
		}

		// configure the token endpoint
		BeanDefinitionBuilder tokenEndpointBean = BeanDefinitionBuilder.rootBeanDefinition(TokenEndpoint.class);
		tokenEndpointBean.addPropertyReference("tokenGranter", tokenGranterRef);
		parserContext.getRegistry().registerBeanDefinition("oauth2TokenEndpoint", tokenEndpointBean.getBeanDefinition());

		// We aren't defining a filter...
		return null;

	}

}
