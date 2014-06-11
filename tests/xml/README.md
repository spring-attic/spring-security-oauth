This project is for integration testing the XML configuration features
of
[Spring OAuth2](https://github.com/spring-projects/spring-security-oauth).
They use a mixture of Java (`@Configuration`) and XML to configure
OAuth clients and servers, but only using XML for the Spring OAuth
bits. Since Spring Security cannot be used with a mixture of
`@Configuration` and XML this is probably not the nicest way to do
things (pure XML or pure Java would probably be better). Pure Java
versions of the same apps can be found
[here](https://github.com/dsyer/spring-oauth-integration-tests).

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
