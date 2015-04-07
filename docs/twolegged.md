---
title: Docs
layout: default
home: ../
---


# 2-Legged OAuth

Two-legged OAuth (also known as "signed fetch") is basically OAuth without the user. It's a way for a consumer (i.e. client) to make a signed request
to a provider (i.e. server) by leveraging the OAuth signature algorithm. This means that the provider has an extra level of trust with the consumer and will
therefore provide data to the consumer without making an end-user authorize a token.

This has particular applicability to gadget frameworks. For example, [OpenSocial](http://www.opensocial.org/) platforms often use 2-legged OAuth so gadget
developers can have the gadget (the OAuth consumer) make Web service requests to their remote server (the OAuth provider). Since the gadget developer and
the server developer are often the same entity, the server can trust the gadget without the need for the gadget to obtain special permission from the user to
access the user's data.

To implement 2-legged OAuth using _OAuth for Spring Security_, all that is needed is for the provider to indicate that a specific consumer has an extra
level of trust. To do this, make sure your implementation of [`ConsumerDetailsService`][ConsumerDetailsService] returns instances of 
[`ConsumerDetails`][ConsumerDetails] that implement [`ExtraTrustConsumerDetails`][ExtraTrustConsumerDetails]. Then, for each consumer
that doesn't need to obtain a user-authorized token, make sure [`ExtraTrustConsumerDetails.isRequiredToObtainAuthenticatedToken()`][isRequiredToObtainAuthenticatedToken]
returns `false`.

In many instances, providers may want to manage the authentication that is set up in the security context. By default for 2-legged OAuth, only the consumer's
authentication will be set up in the context. However, if a user authentication is needed in the context, provide an alternate implementation of
`org.springframework.security.oauth.provider.OAuthAuthenticationHandler` that loads the user authentication, and provide a reference to the alternate
implementation using the "auth-handler-ref" attribute of the "provider" configuration element.

[ConsumerDetailsService]: http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth/provider/ConsumerDetailsService.html
[ConsumerDetails]: http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth/provider/ConsumerDetails.html
[ExtraTrustConsumerDetails]: http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth/provider/ExtraTrustConsumerDetails.html
[isRequiredToObtainAuthenticatedToken]: http://docs.spring.io/spring-security/oauth/apidocs/org/springframework/security/oauth/provider/ExtraTrustConsumerDetails.html#isRequiredToObtainAuthenticatedToken()
