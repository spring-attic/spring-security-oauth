/*
 * Copyright 2006-2010 the original author or authors.
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
package org.springframework.security.oauth2.client.test;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.net.HttpURLConnection;
import java.net.URI;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.config.RequestConfig.Builder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.protocol.HttpContext;
import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.internal.AssumptionViolatedException;
import org.junit.internal.runners.statements.RunBefores;
import org.junit.rules.TestWatchman;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.Statement;
import org.junit.runners.model.TestClass;
import org.springframework.beans.BeanUtils;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.ClassUtils;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;

/**
 * <p>
 * A rule that sets up an OAuth2 context for tests and makes the access token available
 * inside a test method. In combination with the {@link OAuth2ContextConfiguration}
 * annotation provides a number of different strategies for configuring an
 * {@link OAuth2ProtectedResourceDetails} instance that will be used to create the OAuth2
 * context for tests. Example:
 * </p>
 * 
 * <pre>
 * &#064;OAuth2ContextConfiguration(ResourceOwnerPasswordProtectedResourceDetails.class)
 * public class MyIntegrationTests implements RestTemplateHolder {
 * 
 * 	&#064;Rule
 * 	public OAuth2ContextSetup context = OAuth2ContextSetup.withEnvironment(this,
 * 			TestEnvironment.instance());
 * 
 * 	&#064;Test
 * 	public void testSomethingWithClientCredentials() {
 * 		// This call will be authenticated with the client credentials in
 * 		// MyClientDetailsResource
 * 		getRestTemplate().getForObject(&quot;http://myserver/resource&quot;, String.class);
 * 	}
 * 
 * 	// This class is used to initialize the OAuth2 context for the test methods.
 * 	static class MyClientDetailsResource extends
 * 			ResourceOwnerPasswordProtectedResourceDetails {
 * 		public MyClientDetailsResource(Environment environment) {
 *             ... do stuff with environment to initialize the password credentials
 *         }
 * 	}
 * 
 * }
 * </pre>
 * 
 * @see OAuth2ContextConfiguration
 * @see BeforeOAuth2Context
 * 
 * @author Dave Syer
 * 
 */
@SuppressWarnings("deprecation")
public class OAuth2ContextSetup extends TestWatchman {

	private static Log logger = LogFactory.getLog(OAuth2ContextSetup.class);

	private OAuth2ProtectedResourceDetails resource;

	private OAuth2RestTemplate client;

	private Map<String, String> parameters = new LinkedHashMap<String, String>();

	private final RestTemplateHolder clientHolder;

	private final TestAccounts testAccounts;

	private OAuth2AccessToken accessToken;

	private boolean initializeAccessToken = true;

	private RestOperations savedClient;

	private AccessTokenProvider accessTokenProvider;

	private final Environment environment;

	/**
	 * Create a new client that can inject an Environment into its protected resource
	 * details.
	 * 
	 * @param clientHolder receives an OAuth2RestTemplate with the authenticated client
	 * for the duration of a test
	 * @param environment a Spring Environment that can be used to initialize the client
	 * 
	 * @return a rule that wraps test methods in an OAuth2 context
	 */
	public static OAuth2ContextSetup withEnvironment(RestTemplateHolder clientHolder,
			Environment environment) {
		return new OAuth2ContextSetup(clientHolder, null, environment);
	}

	/**
	 * Create a new client that can inject a {@link TestAccounts} instance into its
	 * protected resource details.
	 * 
	 * @param clientHolder receives an OAuth2RestTemplate with the authenticated client
	 * for the duration of a test
	 * @param testAccounts a test account generator that can be used to initialize the
	 * client
	 * 
	 * @return a rule that wraps test methods in an OAuth2 context
	 */
	public static OAuth2ContextSetup withTestAccounts(RestTemplateHolder clientHolder,
			TestAccounts testAccounts) {
		return new OAuth2ContextSetup(clientHolder, testAccounts, null);
	}

	/**
	 * Create a new client that knows how to create its protected resource with no
	 * externalization help. Typically it will use resource details which accept an
	 * instance of the current test case (downcasting it from Object). For example
	 * 
	 * <pre>
	 * static class MyClientDetailsResource extends ClientCredentialsProtectedResourceDetails {
	 * 	public MyClientDetailsResource(Object target) {
	 *             MyIntegrationTests test = (MyIntegrationTests) target;
	 *             ... do stuff with test instance to initialize the client credentials
	 *         }
	 * }
	 * </pre>
	 * 
	 * @param clientHolder receives an OAuth2RestTemplate with the authenticated client
	 * for the duration of a test
	 * 
	 * @return a rule that wraps test methods in an OAuth2 context
	 */
	public static OAuth2ContextSetup standard(RestTemplateHolder clientHolder) {
		return new OAuth2ContextSetup(clientHolder, null, null);
	}

	private OAuth2ContextSetup(RestTemplateHolder clientHolder,
			TestAccounts testAccounts, Environment environment) {
		this.clientHolder = clientHolder;
		this.testAccounts = testAccounts;
		this.environment = environment;
	}

	@Override
	public Statement apply(Statement base, FrameworkMethod method, Object target) {
		initializeIfNecessary(method, target);
		return super.apply(base, method, target);
	}

	@Override
	public void starting(FrameworkMethod method) {
		if (resource != null) {
			logger.info("Starting OAuth2 context for: " + resource);
			AccessTokenRequest request = new DefaultAccessTokenRequest();
			request.setAll(parameters);
			client = createRestTemplate(resource, request);
			if (initializeAccessToken) {
				this.accessToken = null;
				this.accessToken = getAccessToken();
			}
			savedClient = clientHolder.getRestTemplate();
			clientHolder.setRestTemplate(client);
		}
	}

	@Override
	public void finished(FrameworkMethod method) {
		if (resource != null) {
			logger.info("Ending OAuth2 context for: " + resource);
			if (savedClient != null) {
				clientHolder.setRestTemplate(savedClient);
			}
		}
	}

	public void setAccessTokenProvider(AccessTokenProvider accessTokenProvider) {
		this.accessTokenProvider = accessTokenProvider;
	}

	public void setParameters(Map<String, String> parameters) {
		this.parameters = parameters;
	}

	/**
	 * Get the current access token. Should be available inside a test method as long as a
	 * resource has been setup with {@link OAuth2ContextConfiguration
	 * &#64;OAuth2ContextConfiguration}.
	 * 
	 * @return the current access token initializing it if necessary
	 */
	public OAuth2AccessToken getAccessToken() {
		if (resource == null || client == null) {
			return null;
		}
		if (accessToken != null) {
			return accessToken;
		}
		if (accessTokenProvider != null) {
			client.setAccessTokenProvider(accessTokenProvider);
		}
		try {
			return client.getAccessToken();
		}
		catch (OAuth2AccessDeniedException e) {
			Throwable cause = e.getCause();
			if (cause instanceof RuntimeException) {
				throw (RuntimeException) cause;
			}
			if (cause instanceof Error) {
				throw (Error) cause;
			}
			throw e;
		}
	}

	/**
	 * @return the client template
	 */
	public OAuth2RestTemplate getRestTemplate() {
		return client;
	}

	/**
	 * @return the current client resource details
	 */
	public OAuth2ProtectedResourceDetails getResource() {
		return resource;
	}

	/**
	 * @return the current access token request
	 */
	public AccessTokenRequest getAccessTokenRequest() {
		return client.getOAuth2ClientContext().getAccessTokenRequest();
	}

	/**
	 * @return the current OAuth2 context
	 */
	public OAuth2ClientContext getOAuth2ClientContext() {
		return client.getOAuth2ClientContext();
	}

	private void initializeIfNecessary(FrameworkMethod method, final Object target) {

		final TestClass testClass = new TestClass(target.getClass());
		OAuth2ContextConfiguration contextConfiguration = findOAuthContextConfiguration(
				method, testClass);
		if (contextConfiguration == null) {
			// Nothing to do
			return;
		}

		this.initializeAccessToken = contextConfiguration.initialize();

		this.resource = creatResource(target, contextConfiguration);

		final List<FrameworkMethod> befores = testClass
				.getAnnotatedMethods(BeforeOAuth2Context.class);
		if (!befores.isEmpty()) {

			logger.debug("Running @BeforeOAuth2Context methods");

			for (FrameworkMethod before : befores) {

				RestOperations savedServerClient = clientHolder.getRestTemplate();

				OAuth2ContextConfiguration beforeConfiguration = findOAuthContextConfiguration(
						before, testClass);
				if (beforeConfiguration != null) {

					OAuth2ProtectedResourceDetails resource = creatResource(target,
							beforeConfiguration);
					AccessTokenRequest beforeRequest = new DefaultAccessTokenRequest();
					beforeRequest.setAll(parameters);
					OAuth2RestTemplate client = createRestTemplate(resource,
							beforeRequest);
					clientHolder.setRestTemplate(client);

				}

				AccessTokenRequest request = new DefaultAccessTokenRequest();
				request.setAll(parameters);
				this.client = createRestTemplate(this.resource, request);

				List<FrameworkMethod> list = Arrays.asList(before);
				try {
					new RunBefores(new Statement() {
						public void evaluate() {
						}
					}, list, target).evaluate();
				}
				catch (AssumptionViolatedException e) {
					throw e;
				}
				catch (RuntimeException e) {
					throw e;
				}
				catch (AssertionError e) {
					throw e;
				}
				catch (Throwable e) {
					logger.debug("Exception in befores", e);
					Assert.assertThat(e, CoreMatchers.not(CoreMatchers.anything()));
				}
				finally {
					clientHolder.setRestTemplate(savedServerClient);
				}

			}

		}

	}

	private OAuth2RestTemplate createRestTemplate(
			OAuth2ProtectedResourceDetails resource, AccessTokenRequest request) {
		OAuth2ClientContext context = new DefaultOAuth2ClientContext(request);
		OAuth2RestTemplate client = new OAuth2RestTemplate(resource, context);
		setupConnectionFactory(client);
		client.setErrorHandler(new DefaultResponseErrorHandler() {
			// Pass errors through in response entity for status code analysis
			public boolean hasError(ClientHttpResponse response) throws IOException {
				return false;
			}
		});
		if (accessTokenProvider != null) {
			client.setAccessTokenProvider(accessTokenProvider);
		}
		return client;
	}

	private void setupConnectionFactory(OAuth2RestTemplate client) {
		if (Boolean.getBoolean("http.components.enabled")
				&& ClassUtils.isPresent("org.apache.http.client.config.RequestConfig",
						null)) {
			client.setRequestFactory(new HttpComponentsClientHttpRequestFactory() {
				@Override
				protected HttpContext createHttpContext(HttpMethod httpMethod, URI uri) {
					HttpClientContext context = HttpClientContext.create();
					context.setRequestConfig(getRequestConfig());
					return context;
				}

				protected RequestConfig getRequestConfig() {
					Builder builder = RequestConfig.custom()
							.setCookieSpec(CookieSpecs.IGNORE_COOKIES)
							.setAuthenticationEnabled(false).setRedirectsEnabled(false);
					return builder.build();
				}
			});
		}
		else {
			client.setRequestFactory(new SimpleClientHttpRequestFactory() {
				@Override
				protected void prepareConnection(HttpURLConnection connection,
						String httpMethod) throws IOException {
					super.prepareConnection(connection, httpMethod);
					connection.setInstanceFollowRedirects(false);
				}
			});
		}
	}

	private OAuth2ProtectedResourceDetails creatResource(Object target,
			OAuth2ContextConfiguration contextLoader) {
		Class<? extends OAuth2ProtectedResourceDetails> type = contextLoader.value();
		if (type == OAuth2ProtectedResourceDetails.class) {
			type = contextLoader.resource();
		}
		Constructor<? extends OAuth2ProtectedResourceDetails> constructor = ClassUtils
				.getConstructorIfAvailable(type, TestAccounts.class);
		if (constructor != null && testAccounts != null) {
			return BeanUtils.instantiateClass(constructor, testAccounts);
		}
		constructor = ClassUtils.getConstructorIfAvailable(type, Environment.class);
		if (constructor != null && environment != null) {
			return BeanUtils.instantiateClass(constructor, environment);
		}
		constructor = ClassUtils.getConstructorIfAvailable(type, Object.class);
		if (constructor != null) {
			return BeanUtils.instantiateClass(constructor, target);
		}
		// Fallback to default constructor
		return BeanUtils.instantiate(type);
	}

	private OAuth2ContextConfiguration findOAuthContextConfiguration(
			FrameworkMethod method, TestClass testClass) {
		OAuth2ContextConfiguration methodConfiguration = method
				.getAnnotation(OAuth2ContextConfiguration.class);
		if (methodConfiguration != null) {
			return methodConfiguration;
		}
		if (testClass.getJavaClass()
				.isAnnotationPresent(OAuth2ContextConfiguration.class)) {
			return testClass.getJavaClass().getAnnotation(
					OAuth2ContextConfiguration.class);
		}
		return null;
	}

}
