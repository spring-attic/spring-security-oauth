This project shows what you can do with the minimum configuration to
set up an Authorization Server with a custom grant type. 

For the Authorization Server you need to `@EnableAuthorizationServer`
and also configure at least one client registration
(`OAuth2ClientDetails`). You can see this is the bulk of
`Application.java`. 

An `AuthenticationManager` is created by Spring Boot (it has a single
user, named "user", with password "password", per
`application.yml`). It is needed in the Authorization Server to
provide authentication for the Resource Owner Password grant type.
