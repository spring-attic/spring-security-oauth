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

import java.util.List;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.oauth2.provider.AccessGrantAuthenticationProvider;
import org.springframework.security.oauth2.provider.client.ClientCredentialsAuthenticationProvider;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.UnconfirmedAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpoint;
import org.springframework.security.oauth2.provider.filter.CompositeFilter;
import org.springframework.security.oauth2.provider.filter.EndpointValidationFilter;
import org.springframework.security.oauth2.provider.filter.OAuth2ExceptionHandlerFilter;
import org.springframework.security.oauth2.provider.filter.OAuth2ProtectedResourceFilter;
import org.springframework.security.oauth2.provider.password.ClientPasswordAuthenticationProvider;
import org.springframework.security.oauth2.provider.refresh.RefreshAuthenticationProvider;
import org.springframework.security.oauth2.provider.token.InMemoryOAuth2ProviderTokenServices;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.w3c.dom.Element;

/**
 * Parser for the OAuth "provider" element.
 * 
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class OAuth2ProviderBeanDefinitionParser extends AbstractBeanDefinitionParser {

	public static String OAUTH2_AUTHENTICATION_MANAGER = "OAuth2" + BeanIds.AUTHENTICATION_MANAGER;

	@Override
	protected AbstractBeanDefinition parseInternal(Element element, ParserContext parserContext) {

		String resourceId = element.getAttribute("resource-id");
		String clientDetailsRef = element.getAttribute("client-details-service-ref");
		String tokenServicesRef = element.getAttribute("token-services-ref");
		String tokenEndpointUrl = element.getAttribute("token-endpoint-url");
		String authorizationEndpointUrl = element.getAttribute("authorization-endpoint-url");
		String defaultGrantType = element.getAttribute("default-grant-type");
		String serializerRef = element.getAttribute("serialization-service-ref");
		String grantManagerRef = element.getAttribute("grant-manager-ref");
		String redirectStrategyRef = element.getAttribute("redirect-strategy-ref");

		if (!StringUtils.hasText(tokenServicesRef)) {
			tokenServicesRef = "oauth2TokenServices";
			BeanDefinitionBuilder tokenServices = BeanDefinitionBuilder
					.rootBeanDefinition(InMemoryOAuth2ProviderTokenServices.class);
			parserContext.getRegistry().registerBeanDefinition(tokenServicesRef, tokenServices.getBeanDefinition());
		}

		BeanDefinitionBuilder clientAuthProvider = BeanDefinitionBuilder
				.rootBeanDefinition(AccessGrantAuthenticationProvider.class);
		if (StringUtils.hasText(clientDetailsRef)) {
			clientAuthProvider.addPropertyReference("clientDetailsService", clientDetailsRef);
		}
		parserContext.getRegistry().registerBeanDefinition("oauth2ClientProvider",
				clientAuthProvider.getBeanDefinition());

		List<BeanMetadataElement> providers = new ManagedList<BeanMetadataElement>();
		providers.add(clientAuthProvider.getBeanDefinition());

		BeanDefinitionBuilder exceptionHandler = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2ExceptionHandlerFilter.class);
		if (StringUtils.hasText(serializerRef)) {
			exceptionHandler.addPropertyReference("serializationService", serializerRef);
		}

		ManagedList<BeanMetadataElement> filters = new ManagedList<BeanMetadataElement>();

		parserContext.getRegistry().registerBeanDefinition("oauth2ExceptionHandlerFilter",
				exceptionHandler.getBeanDefinition());
		filters.add(new RuntimeBeanReference("oauth2ExceptionHandlerFilter"));

		BeanDefinitionBuilder endpointValidationFilterBean = BeanDefinitionBuilder
				.rootBeanDefinition(EndpointValidationFilter.class);
		if (StringUtils.hasText(tokenEndpointUrl)) {
			endpointValidationFilterBean.addPropertyValue("tokenEndpointUrl", tokenEndpointUrl);
		}
		if (StringUtils.hasText(authorizationEndpointUrl)) {
			endpointValidationFilterBean.addPropertyValue("authorizationEndpointUrl", authorizationEndpointUrl);
		}

		filters.add(endpointValidationFilterBean.getBeanDefinition());

		Element authorizationCodeElement = DomUtils.getChildElementByTagName(element, "authorization-code");
		if (authorizationCodeElement == null
				|| !"true".equalsIgnoreCase(authorizationCodeElement.getAttribute("disabled"))) {
			// authorization code grant configuration.
			String approvalPage = authorizationCodeElement == null ? null : authorizationCodeElement
					.getAttribute("user-approval-page");
			String approvalHandlerRef = authorizationCodeElement == null ? null : authorizationCodeElement
					.getAttribute("approval-handler-ref");
			String approvalParameter = authorizationCodeElement == null ? null : authorizationCodeElement
					.getAttribute("approval-parameter-name");
			String authorizationCodeServices = authorizationCodeElement == null ? null : authorizationCodeElement
					.getAttribute("services-ref");
			String redirectResolverRef = authorizationCodeElement == null ? null : authorizationCodeElement
					.getAttribute("redirect-resolver-ref");
			String authenticationCacheRef = authorizationCodeElement == null ? null : authorizationCodeElement
					.getAttribute("authentication-cache-ref");
			String authorizationCodeRedirectStrategyRef = authorizationCodeElement == null ? null
					: authorizationCodeElement.getAttribute("redirect-strategy-ref");
			if (!StringUtils.hasText(authorizationCodeRedirectStrategyRef)) {
				authorizationCodeRedirectStrategyRef = redirectStrategyRef;
			}

			BeanDefinitionBuilder authorizationEndpointBean = BeanDefinitionBuilder
					.rootBeanDefinition(AuthorizationEndpoint.class);

			if (!StringUtils.hasText(approvalParameter)) {
				// TODO: allow customization of approval parameter
				// authorizationEndpointBean.addPropertyValue("approvalParameter", approvalParameter);
			}
			if (StringUtils.hasText(authenticationCacheRef)) {
				authorizationEndpointBean.addPropertyReference("authenticationCache", authenticationCacheRef);
			}

			if (!StringUtils.hasText(authorizationCodeServices)) {
				authorizationCodeServices = "oauth2AuthorizationCodeServices";
				BeanDefinitionBuilder authorizationCodeServicesBean = BeanDefinitionBuilder
						.rootBeanDefinition(InMemoryAuthorizationCodeServices.class);
				parserContext.getRegistry().registerBeanDefinition(authorizationCodeServices,
						authorizationCodeServicesBean.getBeanDefinition());
			}

			if (StringUtils.hasText(clientDetailsRef)) {
				authorizationEndpointBean.addPropertyReference("clientDetailsService", clientDetailsRef);
			}
			if (StringUtils.hasText(redirectResolverRef)) {
				authorizationEndpointBean.addPropertyReference("redirectResolver", redirectResolverRef);
			}
			if (StringUtils.hasText(authenticationCacheRef)) {
				authorizationEndpointBean.addPropertyReference("authenticationCache", authenticationCacheRef);
			}
			if (StringUtils.hasText(authorizationCodeRedirectStrategyRef)) {
				authorizationEndpointBean
						.addPropertyReference("redirectStrategy", authorizationCodeRedirectStrategyRef);
			}
			if (StringUtils.hasText(approvalPage)) {
				authorizationEndpointBean.addPropertyValue("userApprovalPage", approvalPage);
			}
			authorizationEndpointBean.addPropertyReference("authorizationCodeServices", authorizationCodeServices);
			if (StringUtils.hasText(approvalHandlerRef)) {
				authorizationEndpointBean.addPropertyReference("userApprovalHandler", approvalHandlerRef);
			}

			BeanDefinitionBuilder authorizationCodeProvider = BeanDefinitionBuilder
					.rootBeanDefinition(UnconfirmedAuthorizationCodeAuthenticationProvider.class);
			authorizationCodeProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
			authorizationCodeProvider.addPropertyReference("authorizationCodeServices", authorizationCodeServices);

			providers.add(authorizationCodeProvider.getBeanDefinition());

			parserContext.getRegistry().registerBeanDefinition("oauth2AuthorizationCodeFilter",
					authorizationEndpointBean.getBeanDefinition());

			// end authorization code provider configuration.
		}

		// configure the client password mechanism.
		BeanDefinitionBuilder clientPasswordProvider = BeanDefinitionBuilder
				.rootBeanDefinition(ClientPasswordAuthenticationProvider.class);
		clientPasswordProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
		providers.add(clientPasswordProvider.getBeanDefinition());
		parserContext.getRegistry().registerBeanDefinition("oauth2ClientPasswordProvider",
				clientPasswordProvider.getBeanDefinition());

		// configure the client credentials mechanism
		BeanDefinitionBuilder clientCredentialsProvider = BeanDefinitionBuilder
				.rootBeanDefinition(ClientCredentialsAuthenticationProvider.class);
		clientCredentialsProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
		providers.add(clientCredentialsProvider.getBeanDefinition());
		parserContext.getRegistry().registerBeanDefinition("oauth2ClientCredentialsProvider",
				clientCredentialsProvider.getBeanDefinition());

		// configure the refresh token mechanism.
		BeanDefinitionBuilder refreshTokenProvider = BeanDefinitionBuilder
				.rootBeanDefinition(RefreshAuthenticationProvider.class);
		refreshTokenProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
		providers.add(refreshTokenProvider.getBeanDefinition());
		parserContext.getRegistry().registerBeanDefinition("oauth2RefreshProvider",
				refreshTokenProvider.getBeanDefinition());

		// configure the token endpoint
		BeanDefinitionBuilder tokenEndpointBean = BeanDefinitionBuilder.rootBeanDefinition(TokenEndpoint.class);
		if (StringUtils.hasText(defaultGrantType)) {
			tokenEndpointBean.addPropertyValue("defaultGrantType", defaultGrantType);
		}
		if (StringUtils.hasText(grantManagerRef)) {
			tokenEndpointBean.addPropertyReference("grantManager", grantManagerRef);
		}
		tokenEndpointBean.addPropertyReference("tokenServices", tokenServicesRef);
		tokenEndpointBean.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);
		parserContext.getRegistry().registerBeanDefinition("tokenEndpoint", tokenEndpointBean.getBeanDefinition());

		// configure the protected resource filter
		BeanDefinitionBuilder protectedResourceFilterBean = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2ProtectedResourceFilter.class);
		protectedResourceFilterBean.addPropertyReference("tokenServices", tokenServicesRef);
		if (StringUtils.hasText(resourceId)) {
			protectedResourceFilterBean.addPropertyValue("resourceId", resourceId);
		}
		parserContext.getRegistry().registerBeanDefinition("oauth2ProtectedResourceFilter",
				protectedResourceFilterBean.getBeanDefinition());
		filters.add(new RuntimeBeanReference("oauth2ProtectedResourceFilter"));

		// instantiate the oauth provider manager...
		BeanDefinitionBuilder oauthProviderManagerBean = BeanDefinitionBuilder
				.rootBeanDefinition(ProviderManager.class);
		oauthProviderManagerBean.addPropertyReference("parent", BeanIds.AUTHENTICATION_MANAGER);
		oauthProviderManagerBean.addPropertyValue("providers", providers);
		parserContext.getRegistry().registerBeanDefinition(OAUTH2_AUTHENTICATION_MANAGER,
				oauthProviderManagerBean.getBeanDefinition());

		BeanDefinitionBuilder filterChain = BeanDefinitionBuilder.rootBeanDefinition(CompositeFilter.class);
		filterChain.addPropertyValue("filters", filters);
		return filterChain.getBeanDefinition();
	}

}
