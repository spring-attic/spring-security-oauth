---
title: Docs
layout: default
home: ../
---


# OAuth 2 Developers Guide

## Introduction

This is the user guide for the support for [`OAuth 2.0`](https://tools.ietf.org/html/draft-ietf-oauth-v2). For OAuth 1.0, everything is different, so [see its user guide](oauth1.html).

This user guide is divided into two parts, the first for the OAuth 2.0 provider, the second for the OAuth 2.0 client.

## OAuth 2.0 Provider

The OAuth 2.0 provider mechanism is responsible for exposing OAuth 2.0 protected resources. The configuration involves establishing the OAuth 2.0 clients that can access its protected resources on behalf of a user. The provider does this by managing and verifying the OAuth 2.0 tokens that can be used to access the protected resources. Where applicable, the provider must also supply an interface for the user to confirm that a client can be granted access to the protected resources (i.e. a confirmation page).

### Managing Clients

The entry point into your database of clients is defined by the [`ClientDetailsService`][ClientDetailsService]. You must define your own `ClientDetailsService` that will load [`ClientDetails`][ClientDetails] by the . Note the existence of an [in-memory implementation][InMemoryClientDetailsService] of `ClientDetailsService`.

When implementing your `ClientDetailsService` consider returning instances of (or extending) [`BaseClientDetails`][BaseClientDetails].

### Managing Tokens

The [`AuthorizationServerTokenServices`][AuthorizationServerTokenServices] interface defines the operations that are necessary to manage OAuth 2.0 tokens. Note the following:

* When an access token is created, the authentication must be stored so that the subsequent access token can reference it.
* The access token is used to load the authentication that was used to authorize its creation.

When creating your `AuthorizationServerTokenServices` implementation, you may want to consider using the [`RandomValueTokenServices`][RandomValueTokenServices] which creates tokens via random value and handles everything except for the persistence of the tokens which it delegates to a `TokenStore`.

There is an [in-memory implementation][InMemoryTokenStore] of the `TokenStore` that may be suitable.

## OAuth 2.0 Provider Implementation

The provider role in OAuth 2.0 is actually split between Authorization Service and Resource Service, and while these sometimes reside in the same application, with Spring Security OAuth you have the option to split them across two applications, and also to have multiple Resource Services that share an Authorization Service. The requests for the tokens are handled by Spring MVC controller endpoints, and access to protected resources is handled by standard Spring Security request filters. The following endpoints are required in the Spring Security filter chain in order to implement OAuth 2.0 Authorization Server:

* [`AuthorizationEndpoint`][AuthorizationEndpoint] is used to service requests for authorization. Default URL: `/oauth/authorize`.
* [`TokenEndpoint`][TokenEndpoint] is used to service requests for access tokens. Default URL: `/oauth/token`.

The following filters are required to implement an OAuth 2.0 Resource Server:

* The [`OAuth2ExceptionHandlerFilter`][OAuth2ExceptionHandlerFilter] is used to handle any errors.
* The [`OAuth2AuthenticationProcessingFilter`][OAuth2AuthenticationProcessingFilter] is used to load the Authentication for the request given an authenticated access token.

For all the OAuth 2.0 provider features, configuration is simplified using the custom spring configuration elements. The schema for these elements rests at [https://www.springframework.org/schema/security/spring-security-oauth2.xsd][oauth2.xsd]. The namespace is `http://www.springframework.org/schema/security/oauth2`.

## Authorization Server Configuration

As you configure the Authorization Server, you have to consider the grant type that the client is to use to obtain an access token from the end-user (e.g. authorization code, user credentials, refresh token). The configuration of the server is used to provide implementations of the client details service and token services and to enable or disable certain aspects of the mechanism globally. Note, however, that each client can be configured specifically with permissions to be able to use certain authorization mechanisms and access grants. I.e. just because your provider is configured to support the "client credentials" grant type, doesn't mean that a specific client is authorized to use that grant type.

The `<authorization-server/>` element is used to configure the OAuth 2.0 Authorization Server mechanism. The following attributes can be applied to the `authorization-server` element:

* `client-details-service-ref`: The reference to the bean that defines the client details service.
* `token-services-ref`: The reference to the bean that defines the token services.

An important aspect of the provider configuration is the way that a authorization code is supplied to an OAuth client. A authorization code is obtained by the OAuth client by directing the end-user to an authorization page where the user can enter her credentials, resulting in a redirection from the provider authorization server back to the OAuth client with the authorization code. Examples of this are elaborated in the OAuth 2 specification.

### Grant Types

The authorization code grant type is configured via the `authorization-code` child element of the `authorization-server` element. The `authorization-code` element supports the following attributes:

* `disabled`: Boolean value specifying whether the authorization code mechanism is disabled. This effectively disables the authorization code grant mechanism.
* `services-ref`: The reference to the bean that defines the authorization code services (instance of `org.springframework.security.oauth2.provider.code.AuthorizationCodeServices`)
* `user-approval-page`: The URL of the page that handles the user approval form.
* `approval-parameter-name`: The name of the form parameter that is used to indicate user approval of the client authentication request.

Other grant types are also included as child elements of the `authorization-server`.

### Configuring Client Details

The `client-details-service` element is used to define an in-memory implementation of the client details service. It takes an `id` attribute and an arbitrary number of `client` child elements that define the following attributes for each client:

* `client-id`: (required) The client id.
* `secret`: (required) The client secret, if any.
* `scope`: The scope to which the client is limited (comma-separated). If scope is undefined or empty (the default) the client is not limited by scope.
* `authorized-grant-types`: Flows that are authorized for the client to use (comma-separated). Default value is "web\_server".
* `authorities`: Authorities that are granted to the client (comma-separated).

### Configuring the Endpoint URLs

The `<authorization-server/>` element has some attributes that can be used to change the default endpoint URLs:

* `authorization-endpoint-url`: The URL at which a request for an authorization will be serviced (defaults to `/oauth/authorize`). This URL should be protected using Spring Security so that it is only accessible to authenticated users.
* `token-endpoint-url`: The URL at which a request for an access token will be serviced (defaults to `/oauth/token`). This URL should be accessible to anonymous users.

If the endpoint URLs are changed in this way via the namespace, then an extra bean definition for a servlet Filter is created with id `oauth2EndpointUrlFilter`. This has to be mapped in your servlet container so that incoming requests with those paths are recognized by the Spring dispatcher servlet. The filter definition in `web.xml` would look like this:

    <filter>
        <filter-name>oauth2EndpointUrlFilter</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
        <init-param>
            <param-name>contextAttribute</param-name>
            <param-value>org.springframework.web.servlet.FrameworkServlet.CONTEXT.spring</param-value>
        </init-param>
    </filter>

    <filter-mapping>
        <filter-name>oauth2EndpointUrlFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>


This filter has to be applied in the right order, so make sure the mapping appears in `web.xml` _before_ the mapping for the Spring Security filter.

### Configuring An OAuth-Aware Expression Handler

You may want to take advantage of Spring Security's [expression-based access control][expressions]. You can register a oauth-aware expression handler with the `expression-handler` element. Use the id of the oauth expression handler to add oauth-aware expressions to the built-in expressions.

The expressions include _oauth2.clientHasRole_, _oauth2.clientHasAnyRole_, and _oath2.denyClient_ which can be used to provide access based on the role of the oauth client.

## Resource Server Configuration

You need to supply the `<resource-server/>` element with an `id` attribute - this is the bean id for a servlet `Filter` that can be added to the standard Spring Security chain, e.g.

    <http access-denied-page="/login.jsp" ...>
        <intercept-url pattern="/photos" access="ROLE_USER,SCOPE_READ" />
        ...
        <custom-filter ref="oauth2ProviderFilter" before="PRE_AUTH_FILTER"/>
    </http>

    <oauth:resource-server id="oauth2ProviderFilter" .../>


The following attributes can be applied to the `resource-server` element:

* `token-services-ref`: The reference to the bean that defines the token services.
* `resource-id`: The id for the resource (optional, but recommended and will be validated by the auth server if present)

## OAuth 2.0 Client

The OAuth 2.0 client mechanism is responsible for access the OAuth 2.0 protected resources of other servers. The configuration involves establishing the relevant protected resources to which users might have access. The client also needs to be supplied with mechanisms for storing authorization codes and access tokens for users.

### Protected Resource Configuration

Protected resources can be defined using the `resource` configuration element. Each `resource` element is effectively a definition of a bean that is an instance of [`OAuth2ProtectedResourceDetails`][OAuth2ProtectedResourceDetails]. The `resource` element supports the following attributes:

* `id`: The id of the resource. The id is only used by the client to lookup the resource; it's never used in the OAuth protocol. It's also used as the id of the bean.
* `type`: The type (i.e. "grant type") of the resource. This is used to specify how an access token is to be obtained for this resource. Valid values include "authorization\_code", "password", and "assertion". Default value is "authorization\_code".
* `client-id`: The OAuth client id. This is the id by which the OAuth provider identifies your client.
* `client-secret`: The secret associated with the resource. By default, no secret is empty.
* `access-token-uri`: The URI of the provider OAuth endpoint that provides the access token.
* `user-authorization-uri`: The uri to which the user will be redirected if the user is ever needed to authorize access to the resource. Note that this is not always required, depending on which OAuth 2 profiles are supported.
* `scope`: Comma-separted list of strings specifying the scope of the access to the resource. By default, no scope will be specified.
* `client-authentication-scheme`: The scheme used by your client to authenticate to the access token endpoint. Suggested values: "http\_basic" and "form". Default: "http\_basic". See section 2.1 of the OAuth 2 spec.

### Client Configuration

For the OAuth 2.0 client, configuration is simplified using the custom spring configuration elements. The schema for these elements rests at [https://www.springframework.org/schema/security/spring-security-oauth2.xsd][oauth2.xsd]. The namespace is `http://www.springframework.org/schema/security/oauth2`. You need to supply the `<client/>` element with an `id` attribute - this is the bean id for a servlet `Filter` that must be added to the standard Spring Security chain, e.g.

    <http access-denied-page="/login.jsp" ...>
        <intercept-url pattern="/photos" access="ROLE_USER,SCOPE_READ" />
        ...
        <custom-filter ref="oauth2ClientFilter" after="EXCEPTION_TRANSLATION_FILTER"/>
    </http>

    <oauth:client id="oauth2ClientFilter" />

This filter will be needed to store the current request and context, so in the case of needing to authenticate during a request it will manage the redirection to and from the OAuth authentication uri.

### Accessing Protected Resources

Once you've supplied all the configuration for the resources, you can now access those resources. The suggested method for accessing those resources is by using [the `RestTemplate` introduced in Spring 3][restTemplate]. OAuth for Spring Security has provided [an extension of RestTemplate][OAuth2RestTemplate] that only needs to be supplied an instance of [`OAuth2ProtectedResourceDetails`][OAuth2ProtectedResourceDetails].  To use it with user-tokens (authorization code grants) you should consider using the XML namespace shortcut `<oauth:rest-template/>` which creates some request and session scoped context objects so that requests for different users do not collide at runtime.

### Persisting Tokens

A client does not *need* to persist tokens, but it can be nice for users to not be required to approve a new token grant every time the client app is restarted. The [`ClientTokenServices`](/spring-security-oauth2/src/main/java/org/springframework/security/oauth2/client/token/ClientTokenServices.java) interface defines the operations that are necessary to persist OAuth 2.0 tokens for specific users. There is a JDBC implementation provided, but you can if you prefer implement your own service for storing the access tokens and associated authentication instances in a persistent database.
If you want to use this feature you need provide a specially configured [`AccessTokenProviderChain`][AccessTokenProviderChain] to your [`OAuth2RestTemplate`][OAuth2RestTemplate] e.g.

	<oauth:rest-template resource="foo.bar" id="oauthRestTemplate"	access-token-provider="accessTokenProvider" />

	<bean class="org.springframework.security.oauth2.client.token.AccessTokenProviderChain"	id="accessTokenProvider">
		<property name="clientTokenServices" ref="clientTokenServices" />
	</bean>

	<bean class="com.foo.bar.CustomImplementation"	id="clientTokenServices" />

## Customizations for Clients of External OAuth2 Providers

Some external OAuth2 providers (e.g. [Facebook][Facebook]) do not quite implement the specification correctly, or else they are just stuck on an older version of the spec than Spring Security OAuth. To use those providers in your client application you might need to adapt various parts of the client-side infrastructure.

To use Facebook as an example, there is a Facebook feature in the `tonr2` application (you need to change the configuration to add your own, valid, client id and secret - they are easy to generate on the Facebook website).

Facebook token responses also contain a non-compliant JSON entry for the expiry time of the token (they use `expires` instead of `expires_in`), so if you want to use the expiry time in your application you will have to decode it manually using a custom `OAuth2SerializationService`.

  [AuthorizationEndpoint]: https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/endpoint/AuthorizationEndpoint.html "AuthorizationEndpoint"
  [TokenEndpoint]: https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/endpoint/TokenEndpoint.html "TokenEndpoint"
  [RandomValueTokenServices]: https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/token/RandomValueOAuth2ProviderTokenServices.html "RandomValueTokenServices"
  [InMemoryTokenStore]: https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/token/InMemoryTokenStore.html "InMemoryTokenStore"
  [ClientDetailsService]: https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/ClientDetailsService.html "ClientDetailsService"
  [ClientDetails]: https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/ClientDetails.html "ClientDetails"
  [InMemoryClientDetailsService]: https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/InMemoryClientDetailsService.html "InMemoryClientDetailsService"
  [BaseClientDetails]: https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/BaseClientDetails.html "BaseClientDetails"
  [AuthorizationServerTokenServices]: https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/token/AuthorizationServerTokenServices.html "AuthorizationServerTokenServices"
  [OAuth2ExceptionHandlerFilter]: https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/filter/OAuth2ExceptionHandlerFilter.html "OAuth2ExceptionHandlerFilter"
  [OAuth2AuthenticationProcessingFilter]: https://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/filter/OAuth2AuthenticationProcessingFilter.html "OAuth2AuthenticationProcessingFilter"
  [oauth2.xsd]: https://www.springframework.org/schema/security/spring-security-oauth2.xsd "oauth2.xsd"
  [expressions]: https://docs.spring.io/spring-security/site/docs/3.0.x/reference/el-access.html "Expression Access Control"
  
  [AccessTokenProviderChain]: /spring-security-oauth2/src/main/java/org/springframework/security/oauth2/client/token/AccessTokenProviderChain.java
  [OAuth2RestTemplate]: /spring-security-oauth2/src/main/java/org/springframework/security/oauth2/client/OAuth2RestTemplate.java
  [OAuth2ProtectedResourceDetails]: /spring-security-oauth2/src/main/java/org/springframework/security/oauth2/client/resource/OAuth2ProtectedResourceDetails.java
  [restTemplate]: https://docs.spring.io/spring/docs/3.0.x/javadoc-api/org/springframework/web/client/RestTemplate.html "RestTemplate"
  [Facebook]: https://developers.facebook.com/docs/authentication "Facebook"
