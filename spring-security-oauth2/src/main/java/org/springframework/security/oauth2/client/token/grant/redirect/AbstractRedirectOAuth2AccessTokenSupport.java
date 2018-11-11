/*
 * Copyright 2006-2011 the original author or authors.
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
package org.springframework.security.oauth2.client.token.grant.redirect;

import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;

/**
 * Abstract base class providing support for concrete implementations that
 * need to issue redirect instructions to OAuth2 clients (browsers).
 *
 * @author Andy Elliott
 */
public class AbstractRedirectOAuth2AccessTokenSupport extends OAuth2AccessTokenSupport {

    private Oauth2ClientRedirectResolver oauth2ClientRedirectResolver = new DefaultOauth2ClientRedirectResolver();

    /**
     * Set an alternative to the {@link DefaultOauth2ClientRedirectResolver}.
     *
     * @param oauth2ClientRedirectResolver An alternative <code>Oauth2ClientRedirectResolver</code>
     */
    public void setOauth2ClientRedirectResolver(Oauth2ClientRedirectResolver oauth2ClientRedirectResolver) {
        this.oauth2ClientRedirectResolver = oauth2ClientRedirectResolver;
    }

    // Convenience method for concrete classes to call without having to call
    // an oauth2ClientRedirectResolver getter then the resolve method.
    protected String resolveAuthorizationUri(RedirectResourceDetails resource) {
        return oauth2ClientRedirectResolver.resolveAuthorizationUri(resource);
    }
}
