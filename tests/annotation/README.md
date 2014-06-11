This project contains a selection of minimal apps that are functional
OAuth2 Authorization Servers (token issuer) and Resource Servers
(protected API). (You could split the two roles across two
applications if you preferred.) It uses
[Spring Boot](https://github.com/spring-projects/spring-boot) to
provide an embedded servlet container and for defaulting a load of
configuration, so you should be up and running very quickly. There are
integration tests proving that it works and also showing you how to
access it with the Spring `RestTemplate` API.

The apps are in subdirectories:

* vanilla - a basic, no-frills Authorization Server and Resource Server

* jwt - uses Json Web Tokens as the token format

* mappings - changes the default values for the endpoint paths and the
  protected resource paths
  
* approval - an auth server with granular approvals (per scope)

* jdbc - uses JDBC stores for everything

* form - an auth server that accepts form-based client authentication

* multi - an auth server and multiple Resource Servers in one app

* resource - a pure Resoure Server (needs to be paired with an auth
  server and share a token store)

* client - a simple client app

The client is wired to the other servers as long as they run on the
default port of 8080. 


## Building and Running

You need Java (1.7 or better) and Maven (3.0.5 or better):

```
$ mvn test
...
<test run>
```

Each app can be launched from the `main()` method in
`Application.java`, either from an IDE, or from the command line using
`mvn spring-boot:run`. Or you can build an executable JAR and run
that:

```
$ cd vanilla
$ mvn package
$ java -jar target/*.jar
...
<app starts and listens on port 8080>
```

Tests run using the full HTTP protocol against an embedded server on a
random port chosen by the operating system (so it should work
everywhere). In contrast, when the app runs from the `main()` method,
it listens on port 8080 by default.

Here are some curl commands to use to get started:

```
$ curl -H "Accept: application/json" my-client-with-secret:secret@localhost:8080/oauth/token -d grant_type=client_credentials
{... "access_token": "b561ff06-4259-466e-92d8-781db1a51901", ...}
$ TOKEN=b561ff06-4259-466e-92d8-781db1a5190
$ curl -H "Authorization: Bearer $TOKEN" localhost:8080/
Hello World
```

## Running the Client App

To test in a browser you can run one of the servers (see above) and
the client on a different port (it runs on 8081 by default).

```
$ cd client
$ mvn package
$ java -jar target/*.jar 
...
<app starts and listens on port 8081>
```

Go to http://localhost:8081/client and follow the authorization process (the
username and password are `user` and `password`).
