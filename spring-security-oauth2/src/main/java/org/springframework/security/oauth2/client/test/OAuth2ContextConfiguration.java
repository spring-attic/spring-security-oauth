/*
 * Copyright 2002-2011 the original author or authors.
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
package org.springframework.security.oauth2.client.test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;

/**
 * Annotation to signal that an OAuth2 authentication should be created and and provided to the enclosing scope (method
 * or class). Used at the class level it will apply to all test methods (and {@link BeforeOAuth2Context} initializers).
 * Used at the method level it will apply only to the method, overriding any value found on the enclosing class.
 * 
 * @author Dave Syer
 * 
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.TYPE, ElementType.METHOD })
public @interface OAuth2ContextConfiguration {

	/**
	 * The resource type to use when obtaining an access token. The value provided must be a concrete implementation of
	 * {@link OAuth2ProtectedResourceDetails}. An instance will be constructed by the test framework and used to set up
	 * an OAuth2 authentication context. The strategy used for instantiating the value provided might vary depending on
	 * the consumer. Defaults to the value of {@link resource()} if not provided.
	 * 
	 * @see Password
	 * @see Implicit
	 * @see ClientCredentials
	 * 
	 * @return the resource type to use
	 */
	Class<? extends OAuth2ProtectedResourceDetails> value() default OAuth2ProtectedResourceDetails.class;

	/**
	 * The resource type to use when obtaining an access token. Defaults to {@link Password}. Intended to be used as an
	 * alias for {@link #value()}.
	 * 
	 * @return the resource type to use
	 */
	Class<? extends OAuth2ProtectedResourceDetails> resource() default Password.class;

	static class ResourceHelper {
		public static void initialize(OAuth2ProtectedResourceDetails source, BaseOAuth2ProtectedResourceDetails target) {
			target.setClientId(source.getClientId());
			target.setClientSecret(source.getClientSecret());
			target.setScope(source.getScope());
			target.setId(source.getId());
			target.setAccessTokenUri(source.getAccessTokenUri());
		}
	}

	/**
	 * Set up an OAuth2 context for this test using client credentials grant type
	 */
	static class ClientCredentials extends ClientCredentialsResourceDetails {
		public ClientCredentials(TestAccounts testAccounts) {
			ClientCredentialsResourceDetails resource = testAccounts.getDefaultClientCredentialsResource();
			ResourceHelper.initialize(resource, this);
		}
	}

	/**
	 * Set up an OAuth2 context for this test using resource owner password grant type
	 */
	static class Password extends ResourceOwnerPasswordResourceDetails {
		public Password(TestAccounts testAccounts) {
			ResourceOwnerPasswordResourceDetails resource = testAccounts.getDefaultResourceOwnerPasswordResource();
			ResourceHelper.initialize(resource, this);
			setUsername(resource.getUsername());
			setPassword(resource.getPassword());
		}
	}

	/**
	 * Set up an OAuth2 context for this test using implicit grant type
	 */
	static class Implicit extends ImplicitResourceDetails {
		public Implicit(TestAccounts testAccounts) {
			ImplicitResourceDetails resource = testAccounts.getDefaultImplicitResource();
			ResourceHelper.initialize(resource, this);
			setPreEstablishedRedirectUri(resource.getPreEstablishedRedirectUri());
		}
	}

	/**
	 * Flag to indicate whether the access token should be initialized before the test method. If false then the test
	 * method should access the protected resource or explicitly grab the access token before trying to use it. Default
	 * is true, so test methods can just grab the access token if they need it.
	 * 
	 * @return flag to indicate whether the access token should be initialized before the test method
	 */
	boolean initialize() default true;

}