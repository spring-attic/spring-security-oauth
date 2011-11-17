# OAuth 2 Developers Guide

## Introduction

This is the user guide for the support for [OAuth 2.0](http://tools.ietf.org/html/draft-ietf-oauth-v2). For OAuth 1.0, everything is different, so [[see it's user guide|oauth1]].

This user guide is divided into two parts, the first for the OAuth 2.0 provider, the second for the OAuth 2.0 client.

## OAuth 2.0 Provider

The OAuth 2.0 provider mechanism is responsible for exposing OAuth 2.0 protected resources. The configuration involves establishing
the OAuth 2.0 clients that can access its protected resources on behalf of a user. The provider does this by managing and verifying
the OAuth 2.0 tokens that can be used to access the protected resources. Where applicable, the provider must also supply an interface
for the user to confirm that a client can be granted access to the protected resources (i.e. a confirmation page).

### Managing Clients

The entry point into your database of clients is defined by the [`ClientDetailsService`][ClientDetailsService]. You must define your
own `ClientDetailsService` that will load [`ClientDetails`][ClientDetails] by the <client id>.  Note the existence of an
[in-memory implementation][InMemoryClientDetailsService] of `ClientDetailsService`.

When implementing your `ClientDetailsService` consider returning instances of (or extending) [`BaseClientDetails`][BaseClientDetails].

### Managing Tokens

The [`OAuth2ProviderTokenServices`][OAuth2ProviderTokenServices] interface defines the operations that are necessary to manage
OAuth 2.0 tokens. Note the following:

* When an access token is created, the authentication must be stored so that the subsequent access token can reference it.
* The access token is used to load the authentication that was used to authorize its creation.

When creating your `OAuth2ProviderTokenServices` implementation, you may want to consider extending
the [`RandomValueOAuth2ProviderTokenServices`][RandomValueOAuth2ProviderTokenServices] which creates tokens via random value and handles
everything except for the persistence of the tokens.  There is also an [in-memory implementation][InMemoryOAuth2ProviderTokenServices]
of the `OAuth2ProviderTokenServices` that may be suitable.

### OAuth 2.0 Provider Request Filters

The requests for the tokens and for access to protected resources are handled by standard Spring Security request filters. The following filters
are required in the Spring Security filter chain in order to implement OAuth 2.0:

* The [`OAuth2AuthorizationFilter`][OAuth2AuthorizationFilter] is used to service the request for an access token. Default URL: `/oauth/authorize`.
* The [`OAuth2ExceptionHandlerFilter`][OAuth2ExceptionHandlerFilter] is used to handle any errors.
* The [`OAuth2ProtectedResourceFilter`][OAuth2ProtectedResourceFilter] is used to load the Authentication for the request given an authenticated access token.

Other filters are applied according to the different OAuth 2.0 grant types.

### Provider Configuration

For the OAuth 2.0 provider, configuration is simplified using the
custom spring configuration elements. The schema for these elements
rests at
[http://www.springframework.org/schema/security/spring-security-oauth2.xsd](http://www.springframework.org/schema/security/spring-security-oauth2.xsd).
The namespace is
`http://www.springframework.org/schema/security/oauth2`.  You need to
supply the `<provider/>` element with an `id` attribute - this is the
bean id for a servlet `Filter` that can be added to teh standard
Spring Security chain, e.g.

    <http access-denied-page="/login.jsp" ...>
        <intercept-url pattern="/photos" access="ROLE_USER,SCOPE_READ" />
        ...
        <custom-filter ref="oauth2ProviderFilter" after="EXCEPTION_TRANSLATION_FILTER"/>
    </http>

    <oauth:provider id="oauth2ProviderFilter" .../>

As you configure the provider, you have to consider two different pieces to the OAuth 2 authorization mechanism. The first is
the way that the client is to obtain authorization to obtain an access token from the end-user (e.g. authorization code). The
second is the mechanism by which the access token is granted (e.g. authorization code, user credentials, refresh token). The configuration
of the provider is used to provide implementations of the consumer details service and token services and to enable or disable certain
aspects of the mechanism globally. Note, however, that each client can be configured specifically with permissions to be able to use certain
authorization mechanisms and access grants. I.e. just because your provider is configured to support the "client credentials" grant type,
doesn't mean that a specific client is authorized to use that grant type.

The `provider` element is used to configure the OAuth 2.0 provider mechanism. The following attributes can be applied to the `provider` element:

* `client-details-service-ref`: The reference to the bean that defines the client details service.
* `token-services-ref`: The reference to the bean that defines the token services.
* `authorization-endpoint-url`: The URL at which a request for an authorization will be serviced (defaults to `/oauth/authorize`).  This URL should be protected using Spring Security so that it is only accessible to authenticated users.
* `token-endpoint-url`: The URL at which a request for an access token will be serviced (defaults to `/oauth/token`).  This URL should be accessible to anonymous users.

An important aspect of the provider configuration is the way that a authorization code is supplied to an OAuth client. A authorization code
is obtained by the OAuth client by directing the end-user to an authorization page where the user can enter her credentials, resulting in a
redirection from the provider authorization server back to the OAuth client with the authorization code. Examples of this are elaborated in
the OAuth 2 specification.

The provider role in OAuth 2 is actually split between Authorization
Service and Resource Service, and while these sometimes reside in the
same application, with Spring Security OAuth you have the option to
split them across two applications, and also to have multiple Resource
Services that share an Authorization Service.

### Authorization Service Filters

The authorization code mechanism is configured via the `authorization-code` child element of the `provider` element. The `authorization-code` 
element supports the following attributes:

* `disabled`: Boolean value specifying whether the authorization code mechanism is disabled. This effectively disables the authorization
  code grant mechanism.
* `services-ref`: The reference to the bean that defines the authorization code services (instance of `org.springframework.security.oauth2.provider.code.AuthorizationCodeServices`)
* `user-approval-page`: The URL of the page that handles the user approval form.
* `approval-parameter-name`: The name of the form parameter that is used to indicate user approval of the client authentication request.

### Resource Service Filters

A provider that services resource requests from clients needs a
different set of filters to the Authorization Service.

### Configuring Client Details

The `client-details-service` element is used to define an in-memory implementation of the client details service.  It takes an `id` attribute and an
arbitrary number of `client` child elements that define the following attributes for each client:

* `clientId`: (required) The client id.
* `secret`: (required) The client secret, if any.
* `scope`: The scope to which the client is limited (comma-separated). If scope is undefined or empty (the default) the client is not limited by scope.
* `authorizedFlows`: Flows that are authorized for the client to use (comma-separated). Default value is "web_server".
* `authorities`: Authorities that are granted to the client (comma-separated).

### Configuring An OAuth-Aware Expression Handler

You may want to take advantage of Spring Security's [expression-based access control](http://static.springsource.org/spring-security/site/docs/3.0.x/reference/el-access.html).
You can register a oauth-aware expression handler with the `expression-handler` element. Use the id of the oauth expression handler to add oauth-aware
expressions to the built-in expressions.

The expressions include _oauthClientHasRole_, _oauthClientHasAnyRole_, and _denyOAuthClient_ which can be used to provide access based on the role of the
oauth client.

## OAuth 2.0 Client

  The OAuth 2.0 client mechanism is responsible for access the OAuth 2.0 protected resources of other servers. The configuration involves establishing
  the relevant protected resources to which users might have access. The client also needs to be supplied with mechanisms for storing authorization
  codes and access tokens for users.

### Managing Protected Resources

  The entry point into your database of protected resources is defined by the [`OAuth2ProtectedResourceDetailsService`][OAuth2ProtectedResourceDetailsService].
  You must define your own `OAuth2ProtectedResourceDetailsService` that will load [`OAuth2ProtectedResourceDetails`][OAuth2ProtectedResourceDetails]
  by id.  Note the existence of an [in-memory implementation][InMemoryOAuth2ProtectedResourceDetailsService] of `OAuth2ProtectedResourceDetailsService`,
  which might be adequate for your needs. See "Configuring Resource Details" for more information.

### Managing Tokens

  The [`OAuth2ClientTokenServices`][OAuth2ClientTokenServices] interface defines the operations that are necessary to manage OAuth 2.0 tokens for
  specific users. There is an in-memory implementation provided, but it's likely you'll need to implement your own service for storing the access
  tokens and associated authentication instances in a persistent database.

### Client Configuration

For the OAuth 2.0 client, configuration is simplified using the custom
spring configuration elements. The schema for these elements rests at
[http://www.springframework.org/schema/security/spring-security-oauth2.xsd](http://www.springframework.org/schema/security/spring-security-oauth2.xsd).
The namespace is
`http://www.springframework.org/schema/security/oauth2`.  You need to
supply the `<client/>` element with an `id` attribute - this is the
bean id for a servlet `Filter` that can be added to the standard
Spring Security chain, e.g.

    <http access-denied-page="/login.jsp" ...>
        <intercept-url pattern="/photos" access="ROLE_USER,SCOPE_READ" />
        ...
        <custom-filter ref="oauth2ClientFilter" after="EXCEPTION_TRANSLATION_FILTER"/>
    </http>

    <oauth:client id="oauth2ClientFilter" .../>

The `client` element is used to configure the OAuth 2.0 client mechanism. The following attributes can be applied to the `client` element:

* `token-services-ref`: The reference to the bean that stores tokens on behalf of a user. Default value is an instance of [`InMemoryOAuth2ConsumerTokenServices`][InMemoryOAuth2ConsumerTokenServices].
* `resource-details-service-ref`: The reference to the bean that services the known resource details.

### Protected Resource Configuration

Protected resources can be defined using the `resource` configuration element. Each `resource` element is effectively a definition of a bean that is
an instance of [`OAuth2ProtectedResourceDetails`][OAuth2ProtectedResourceDetails]. The `resource` element supports the following attributes:

* `id`: The id of the resource. The id is only used by the client to lookup the resource; it's never used in the OAuth protocol. It's also used as the id of the bean.
* `type`: The type (i.e. "grant type") of the resource. This is used to specify how an access token is to be obtained for this resource. Valid values include "authorization_code", "password", and "assertion". Default value is "authorization_code".
* `clientId`: The OAuth client id. This is the id by with the OAuth provider is to identify your client.
* `accessTokenUri`: The URI of the provider OAuth endpoint that provides the access token.
* `scope`: Comma-separted list of string specifying the scope of the access to the resource. By default, no scope will be specified.
* `clientSecret`: The secret associated with the resource. By default, no secret will be supplied for access to the resource.
* `clientAuthenticationScheme`: The scheme used by your client to authenticate to the access token endpoint. Suggested values: "http_basic" and "form". Default: "http_basic". See section 2.1 of the OAuth 2 spec.
* `userAuthorizationUri`: The uri to which the user will be redirected if the user is ever needed to authorize access to the resource. Note that this is not always required, depending on which OAuth 2 profiles are supported.

### Accessing Protected Resources

Once you've supplied all the configuration for the resources, you can now access those resources. The suggested method for accessing those resources
is by using [the `RestTemplate` introduced in Spring 3](http://static.springsource.org/spring/docs/3.0.x/javadoc-api/org/springframework/web/client/RestTemplate.html).
OAuth for Spring Security has provided [an extension of RestTemplate][OAuth2RestTemplate] that only needs to be supplied an instance of
[`OAuth2ProtectedResourceDetails`][OAuth2ProtectedResourceDetails].

[ClientDetailsService]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/ClientDetailsService.html
[ClientDetails]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/ClientDetails.html
[InMemoryClientDetailsService]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/InMemoryClientDetailsService.html
[BaseClientDetails]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/BaseClientDetails.html
[OAuth2ProviderTokenServices]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/token/OAuth2ProviderTokenServices.html
[RandomValueOAuth2ProviderTokenServices]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/token/RandomValueOAuth2ProviderTokenServices.html
[InMemoryOAuth2ProviderTokenServices]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/token/InMemoryOAuth2ProviderTokenServices.html
[OAuth2AuthorizationFilter]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/filter/OAuth2AuthorizationFilter.html
[OAuth2ExceptionHandlerFilter]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/filter/OAuth2ExceptionHandlerFilter.html
[OAuth2ProtectedResourceFilter]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/provider/filter/OAuth2ProtectedResourceFilter.html
[OAuth2ProtectedResourceDetailsService]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/client/OAuth2ProtectedResourceDetailsService.html
[OAuth2ProtectedResourceDetails]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/client/OAuth2ProtectedResourceDetails.html
[InMemoryOAuth2ProtectedResourceDetailsService]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/client/InMemoryOAuth2ProtectedResourceDetailsService.html
[OAuth2ClientTokenServices]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/client/token/OAuth2ClientTokenServices.html
[OAuth2RestTemplate]: http://static.springsource.org/spring-security/oauth/apidocs/org/springframework/security/oauth2/client/OAuth2RestTemplate.html

## Customizations for Clients of External OAuth2 Providers

Some external OAuth2 providers
(e.g. [Facebook](http://developers.facebook.com/docs/authentication))
do not quite implement the specification correctly, or else they are
just stuck on an older version of the spec than Spring Security OAuth.
To use those providers in your client application you might need to
adapt various parts of the client-side infrastructure.

To use Facebook as an example, there is a Facebook feature in the
`tonr2` application (you need to change the configuration to add your
own, valid, client id and secret - they are easy to generate on the
Facebook website).  At the time of writing, this works, but only with
a small modification.  Look at the `FacebookController` in `tonr2` and
you will find the relevant modifications:

    OAuth2SecurityContext context = OAuth2SecurityContextHolder.getContext();
    if (context != null) {
        // this one is kind of a hack for this application
        // the problem is that the facebook friends page doesn't remove 
        // the 'code=' request parameter.
        ((OAuth2SecurityContextImpl) context).setAuthorizationCode(null);
    }

So in this controller we are using the `OAuth2RestTemplate` as normal,
but we have to defensively modify the security context in the case
that we need to obtain a new access token.

Facebook token responses also contain a non-compliant JSON entry for
the expiry time of the token (they use `expires` instead of
`expires_in`), so if you want to use the expiry time in your
application you will have to decode it manually using a custom
`OAuth2SerializationService`.
