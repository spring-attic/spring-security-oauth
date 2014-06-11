This project shows what you can do with the minimum configuration to
set up an Authorization Server and Resource Server with different
endpoint paths than the defaults.

For the Authorization Server, in addition to the basic "vanilla"
features, we add mappings from "/oauth/token" to "/token" for
instance. The target values for the mappings are injected using
`@Value`, largely to make it easier to test them. You can see this is
the bulk of `Application.java`.

For the Resource Server, in this app we change the default protected
resource patterns to "/" and "/admin/beans". The rest of the app is
protected by HTTP Basic security by default because of the Spring Boot
autoconfiguration features (this is verified in a test case
`ProtectedResourceTests`). We also add an access rule (scope='read' is
required to access both OAuth2 resources).
