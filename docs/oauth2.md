---
title: Docs
layout: default
home: ../
---


# OAuth 2 Developers Guide

## Introduction

This is the user guide for the support for [`OAuth 2.0`](http://tools.ietf.org/html/draft-ietf-oauth-v2). For OAuth 1.0, everything is different, so [see its user guide](oauth1.html).

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

When creating your `AuthorizationServerTokenServices` implementation, you may want to consider using the [`DefaultTokenServices`][DefaultTokenServices] which creates tokens via random value and handles everything except for the persistence of the tokens which it delegates to a `TokenStore`. The default store is an [in-memory implementation][InMemoryTokenStore], but there is also a [jdbc version](JdbcTokenStore) that may be suitable for your needs.

## OAuth 2.0 Provider Implementation

The provider role in OAuth 2.0 is actually split between Authorization Service and Resource Service, and while these sometimes reside in the same application, with Spring Security OAuth you have the option to split them across two applications, and also to have multiple Resource Services that share an Authorization Service. The requests for the tokens are handled by Spring MVC controller endpoints, and access to protected resources is handled by standard Spring Security request filters. The following endpoints are required in the Spring Security filter chain in order to implement OAuth 2.0 Authorization Server:

* [`AuthorizationEndpoint`][AuthorizationEndpoint] is used to service requests for authorization. Default URL: `/oauth/authorize`.
* [`TokenEndpoint`][TokenEndpoint] is used to service requests for access tokens. Default URL: `/oauth/token`.

The following filter is required to implement an OAuth 2.0 Resource Server:

* The [`OAuth2AuthenticationProcessingFilter`][OAuth2AuthenticationProcessingFilter] is used to load the Authentication for the request given an authenticated access token.

For all the OAuth 2.0 provider features, configuration is simplified using special Spring OAuth `@Configuration` adapters.  There is also XML namespace for OAuth configuration and the schema resides at [http://www.springframework.org/schema/security/spring-security-oauth2.xsd][oauth2.xsd]. The namespace is `http://www.springframework.org/schema/security/oauth2`.

## Authorization Server Configuration

As you configure the Authorization Server, you have to consider the grant type that the client is to use to obtain an access token from the end-user (e.g. authorization code, user credentials, refresh token). The configuration of the server is used to provide implementations of the client details service and token services and to enable or disable certain aspects of the mechanism globally. Note, however, that each client can be configured specifically with permissions to be able to use certain authorization mechanisms and access grants. I.e. just because your provider is configured to support the "client credentials" grant type, doesn't mean that a specific client is authorized to use that grant type.

The `@EnableAuthorizationServer` annotation is used to configure the OAuth 2.0 Authorization Server mechanism, together with any `@Beans` that implement `AuthorizationServerConfigurer` (there is a hander adapter implementation with empty methods). The following features are delegated to separate configurers that are created by Spring and passed into the `AuthorizationServerConfigurer`:

* `ClientDetailsServiceConfigurer`: a configurer that defines the client details service. Client details can be initialized, or you can just refer to an existing store.
* `AuthorizationServerSecurityConfigurer`: defines the authorization and token endpoints and the token services.

An important aspect of the provider configuration is the way that an authorization code is supplied to an OAuth client (in the authorization code grant). A authorization code is obtained by the OAuth client by directing the end-user to an authorization page where the user can enter her credentials, resulting in a redirection from the provider authorization server back to the OAuth client with the authorization code. Examples of this are elaborated in the OAuth 2 specification.

In XML there is an `<authorization-server/>` element that is used in a similar way to configure the OAuth 2.0 Authorization Server.

### Grant Types

The grant types supported by the `AuthorizationEndpoint` can be configured via the `AuthorizationServerSecurityConfigurer`. The following properties affect grant types:

* `authenticationManager`: by default all grant types are supported except password grants, which are switched on by injecting an `AuthenticationManager`.
* `authorizationCodeServices`: defines the authorization code services (instance of `org.springframework.security.oauth2.provider.code.AuthorizationCodeServices`) for the auth code grant
* `tokenGranter`: the `TokenGranter` (taking full control of the granting and ignoring the other properties above)

In XML grant types are included as child elements of the `authorization-server`.

### Configuring Client Details

The `ClientDetailsServiceConfigurer` (a callback from your `AuthorizationServerConfigurer`) can be used used to define an in-memory or JDBC implementation of the client details service. Important attributes of a client are

* `clientId`: (required) the client id.
* `secret`: (required for trusted clients) the client secret, if any.
* `scope`: The scope to which the client is limited. If scope is undefined or empty (the default) the client is not limited by scope.
* `authorizedGrantTypes`: Grasnt types that are authorized for the client to use. Default value is empty.
* `authorities`: Authorities that are granted to the client (regular Spring Security authorities).

### Configuring the Endpoint URLs

The `AuthorizationServerSecurityConfigurer` has a `pathMapping()` method. It takes two arguments:

* The default (framework implementation) URL path for the endpoint
* The custom path required (starting with a "/") 

The URL paths provided by the framework are `/oauth/authorize` (the authorization endpoint), `/oauth/token` (the token endpoint), `/oauth/confirm_access` (user posts approval for grants here) and `/oauth/error` (used to render errors in the authorization server).

N.B. the Authorization endpoint `/oauth/authorize` (or its mapped alternative) should be protected using Spring Security so that it is only accessible to authenticated users. The token endpoint is protected by default by Spring OAuth in the `@Configuration` support using HTTP Basic authentication of the client secret, but not in XML (so in that case it should be protected explicitly).

In XML the `<authorization-server/>` element has some attributes that can be used to change the default endpoint URLs in a similar way.

## Customizing the Error Handling

Error handling in an Authorization Server uses standard Spring MVC features, namely `@ExceptionHandler` methods in the endpoints themselves. Users can also provide a `WebResponseExceptionTranslator` to the endpoints themselves which is the best way to change the content of the responses as opposed to the way they are rendered. The rendering of exceptions delegates to `HttpMesssageConverters` (which can be added to the MVC configuration) in the case of token endpoint and to the OAuth error view (`/oauth/error`) in the case of teh authorization endpoint. A whitelabel error endpoint is provided, but users probably need to provide a custom implementation (e.g. just add a `@Controller` with `@RequestMapping("/oauth/error")`).

## Resource Server Configuration

A Resource Server (can be the same as the Authorization Server or a separate application) serves resources that are protected by the OAuth2 token. Spring OAuth provides a Spring Security authentication filter that implements this protection. You can switch it on with `@EnableResourceServer` on an `@Configuration` class, and configure it (as necessary) using a `ResourceServerConfigurer`. The following features can be configured:

* `tokenServices`: the bean that defines the token services (instance of `ResourceServerTokenServices`).
* `resourceId`: the id for the resource (optional, but recommended and will be validated by the auth server if present).

The `@EnableResourceServer` annotation adds a filter of type `OAuth2AuthenticationProcessingFilter` to the Spring Security filter chain.

In XML there is a `<resource-server/>` element with an `id` attribute - this is the bean id for a servlet `Filter` that can be added to the standard Spring Security chain.

### Configuring An OAuth-Aware Expression Handler

You may want to take advantage of Spring Security's [expression-based access control][expressions]. An expression handler will be registered by default in the `@EnableResourceServer` setup. The expressions include _#oauth2.clientHasRole_, _#oauth2.clientHasAnyRole_, and _#oath2.denyClient_ which can be used to provide access based on the role of the oauth client (see `OAuth2SecurityExpressionMethods` for a comprehensive list). In XML you can register a oauth-aware expression handler with the `expression-handler` element of the regular `<http/>` security configuration.

## OAuth 2.0 Client

The OAuth 2.0 client mechanism is responsible for access the OAuth 2.0 protected resources of other servers. The configuration involves establishing the relevant protected resources to which users might have access. The client may also need to be supplied with mechanisms for storing authorization codes and access tokens for users.

### Protected Resource Configuration

Protected resources (or "remote resources") can be defined using bean definitions of type [`OAuth2ProtectedResourceDetails`][OAuth2ProtectedResourceDetails]. A protected resource has the following properties:

* `id`: The id of the resource. The id is only used by the client to lookup the resource; it's never used in the OAuth protocol. It's also used as the id of the bean.
* `clientId`: The OAuth client id. This is the id by which the OAuth provider identifies your client.
* `clientSecret`: The secret associated with the resource. By default, no secret is empty.
* `accessTokenUri`: The URI of the provider OAuth endpoint that provides the access token.
* `scope`: Comma-separted list of strings specifying the scope of the access to the resource. By default, no scope will be specified.
* `clientAuthenticationScheme`: The scheme used by your client to authenticate to the access token endpoint. Suggested values: "http\_basic" and "form". Default: "http\_basic". See section 2.1 of the OAuth 2 spec.

Different grant types have different concrete implementations  of `OAuth2ProtectedResourceDetails` (e.g. `ClientCredentialsResource` for "client_credentials" grant type).  For grant types that require user authorization there is a further property:

* `userAuthorizationUri`: The uri to which the user will be redirected if the user is ever needed to authorize access to the resource. Note that this is not always required, depending on which OAuth 2 profiles are supported.

In XML there is a `<resource/>` element that can be used to create a bean of type `OAuth2ProtectedResourceDetails`. It has attributes matching all the properties above.


### Client Configuration

For the OAuth 2.0 client, configuration is simplified using `@EnableOAuth2Client`. This does 2 things:

* Creates a filter bean (with ID `oauth2ClientContextFilter`) to store the current
request and context. In the case of needing to authenticate during a
request it manages the redirection to and from the OAuth
authentication uri.

* Creates a bean of type `AccessTokenRequest` in request scope. This
can be used by authorization code (or implicit) grant clients to keep
state related to individual users from colliding.

The filter has to be wired into the application (e.g. using a Servlet
initializer or `web.xml` configuration for a `DelegatingFilterProxy`
with the same name). 

The `AccessTokenRequest` can be used in an
`OAuth2RestTemplate` like this:

```
@Resource
@Qualifier("accessTokenRequest")
private AccessTokenRequest accessTokenRequest;

@Bean
@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
public OAuth2RestTemplate sparklrRestTemplate() {
	return new OAuth2RestTemplate(sparklr(), new DefaultOAuth2ClientContext(accessTokenRequest));
}
```

The rest template is placed in session scope to keep the state for
different users separate. Without that you would have to manage the
equivalent data structure yourself on the server, mapping incoming
requests to users, and associating each user with a separate instance
of the `OAuth2ClientContext`.

In XML there is a `<client/>` element with an `id` attribute - this is the bean id for a servlet `Filter` that must be mapped as in the `@Configuration` case to a `DelegatingFilterProxy` (with the same name).


### Accessing Protected Resources

Once you've supplied all the configuration for the resources, you can now access those resources. The suggested method for accessing those resources is by using [the `RestTemplate` introduced in Spring 3][restTemplate]. OAuth for Spring Security has provided [an extension of RestTemplate][OAuth2RestTemplate] that only needs to be supplied an instance of [`OAuth2ProtectedResourceDetails`][OAuth2ProtectedResourceDetails].  To use it with user-tokens (authorization code grants) you should consider using the `@EnableOAuth2Client` configuration (or the XML equivalent `<oauth:rest-template/>`) which creates some request and session scoped context objects so that requests for different users do not collide at runtime.

### Persisting Tokens in a Client

A client does not *need* to persist tokens, but it can be nice for users to not be required to approve a new token grant every time the client app is restarted. The [`ClientTokenServices`](/spring-security-oauth2/src/main/java/org/springframework/security/oauth2/client/token/ClientTokenServices.java) interface defines the operations that are necessary to persist OAuth 2.0 tokens for specific users. There is a JDBC implementation provided, but you can if you prefer implement your own service for storing the access tokens and associated authentication instances in a persistent database.
If you want to use this feature you need provide a specially configured `TokenProvider` to the `OAuth2RestTemplate` e.g.

```java
@Bean
@Scope(value = "session", proxyMode = ScopedProxyMode.INTERFACES)
public OAuth2RestOperations restTemplate() {
	OAuth2RestTemplate template = new OAuth2RestTemplate(resource(), new DefaultOAuth2ClientContext(accessTokenRequest));
	AccessTokenProviderChain provider = new AccessTokenProviderChain(Arrays.asList(new AuthorizationCodeAccessTokenProvider()));
	provider.setClientTokenServices(clientTokenServices());
	return template;
}
```

## Customizations for Clients of External OAuth2 Providers

Some external OAuth2 providers (e.g. [Facebook][Facebook]) do not quite implement the specification correctly, or else they are just stuck on an older version of the spec than Spring Security OAuth. To use those providers in your client application you might need to adapt various parts of the client-side infrastructure.

To use Facebook as an example, there is a Facebook feature in the `tonr2` application (you need to change the configuration to add your own, valid, client id and secret - they are easy to generate on the Facebook website).

Facebook token responses also contain a non-compliant JSON entry for the expiry time of the token (they use `expires` instead of `expires_in`), so if you want to use the expiry time in your application you will have to decode it manually using a custom `OAuth2SerializationService`.

  [AuthorizationEndpoint]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/endpoint/AuthorizationEndpoint.html "AuthorizationEndpoint"
  [TokenEndpoint]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/endpoint/TokenEndpoint.html "TokenEndpoint"
  [DefaultTokenServices]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/token/DefaultTokenServices.html "DefaultTokenServices"
  [InMemoryTokenStore]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/token/InMemoryTokenStore.html "InMemoryTokenStore"
  [JdbcTokenStore]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/token/JdbcTokenStore.html "JdbcTokenStore"
  [ClientDetailsService]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/ClientDetailsService.html "ClientDetailsService"
  [ClientDetails]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/ClientDetails.html "ClientDetails"
  [InMemoryClientDetailsService]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/InMemoryClientDetailsService.html "InMemoryClientDetailsService"
  [BaseClientDetails]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/BaseClientDetails.html "BaseClientDetails"
  [AuthorizationServerTokenServices]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/token/AuthorizationServerTokenServices.html "AuthorizationServerTokenServices"
  [OAuth2AuthenticationProcessingFilter]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/filter/OAuth2AuthenticationProcessingFilter.html "OAuth2AuthenticationProcessingFilter"
  [oauth2.xsd]: http://www.springframework.org/schema/security/spring-security-oauth2.xsd "oauth2.xsd"
  [expressions]: http://static.springsource.org/spring-security/site/docs/3.2.x/reference/el-access.html "Expression Access Control"
  
  [AccessTokenProviderChain]: /spring-security-oauth2/src/main/java/org/springframework/security/oauth2/client/token/AccessTokenProviderChain.java
  [OAuth2RestTemplate]: /spring-security-oauth2/src/main/java/org/springframework/security/oauth2/client/OAuth2RestTemplate.java
  [OAuth2ProtectedResourceDetails]: /spring-security-oauth2/src/main/java/org/springframework/security/oauth2/client/resource/OAuth2ProtectedResourceDetails.java
  [restTemplate]: http://static.springsource.org/spring/docs/3.2.x/javadoc-api/org/springframework/web/client/RestTemplate.html "RestTemplate"
  [Facebook]: http://developers.facebook.com/docs/authentication "Facebook"
