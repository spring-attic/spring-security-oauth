This project shows what you can do with the minimum configuration to
set up an Authorization Server and multiple Resource Servers in the
same app.

For the Resource Server all that is needed is the
`@EnableResourceServer` annotation. By default it protects all
resources that are not explicitly ignored and not exposed by the
`AuthorizationEndpoint` (if there is an Authorization Server in the
same application).
