In this project the Authorization Server allows form-based 
authentication on the /oauth/token endpoint. This is not best
practice from a security point of view so it is disabled by default.

In the Authorization Server we call `allowFormAuthenticationForClients()`
on the configurer. That's it.

