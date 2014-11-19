This project shows what you can do with the minimum configuration to
set up an Authorization Server and Resource Server with XML serialization
of access tokens and error responses. 

You need to teach Spring how to serialize `OAuth2AccessTokens` and 
`OAuth2Exceptions` using the converters provided in Spring OAuth. The
steps to do this can be seen in the server (`Application` configuration)
and also in the client (where we inject `HttpMessageConverters` into the
`RestTemplate` used to access resources in the integration tests).