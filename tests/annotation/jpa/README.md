This project shows what you can do with the minimum configuration to
set up an Authorization Server and Resource Server with JDBC backends. 

The Authorization Server has JDBC backends for clients
(`ClientDetailsStore`), tokens (`TokenStore`), authorization codes
(`AuthorizationCodeStore`) and user accounts
(`UserDetailsManager`). Even with these services, a horizontally
scaled Authorization Server needs to be fronted by a load balancer
with sticky sessions (or else a Spring `SessionAttributeStore` should
be provided in addition to wht you see here), if the stateful grant
types are used (authorization code or implicit).

An `AuthenticationManager` is created (it has a single user, named
"user", with password "password", per `application.yml`). It is needed
in the Authorization Server to provide authentication for the Resource
Owner Password grant type.

The Resource Server shares the `TokenStore` with the Authorization
Server, but it doesn't need to know about the other services (so they
could be in-memory if there is a single instance of the Authorization
Server).
