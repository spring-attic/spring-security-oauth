These are the Spring Security OAuth sample apps and integration tests.
They are split into OAuth (1a) and OAuth2 samples.  Look in the
subdirectory `oauth` and `oauth2` respectively for components of the
sample you are interested in.  They are broadly speaking similar
functionally - there are two web apps, one (`sparklr`) is a provider
or OAuth services, and the other (`tonr`) is a consumer of the
services.  The `tonr` app is also able to consume external resources
(e.g. Facebook), and the precise external resource it consumes has
been chosen to show the use of the relevant protocol.

The `sparklr` app is a photo storage and browsing service, but it
doesn't know how to print your photos.  Thats where `tonr` comes in.
You go to `tonr` to browse the photos that are stored in `sparklr` and
"print" them (this feature is not actually implemented).  The `tonr`
app has to get your permission to access the photos, but only for read
access - this is the key separation of concerns that is offered by
OAuth protocols: `sparklr` is able to ask the user to authorize `tonr`
to read his photos for the purpose of printing them.

To run the apps the easiest thing is to first install all the
artifacts using `mvn install` and then go to the `tonr` directory (in
`oauth` or `oauth2`) and run `mvn tomcat7:run`.  You can also use the
command line to build war files with `mvn package` and drop them in
your favourite server, or you can run them directly from an IDE.

Visit `http://localhost:8080/tonr2` in a browser and go to the
`sparklr` tab.  The result should be:

* You are prompted to authenticate with `tonr` (the login screen tells
  you the users available and their passwords)
  
* The correct authorization is not yet in place for `tonr` to access
  your photos on `sparklr` on your behalf, so `tonr` redirects your
  browser to the `sparklr` UI to get the authorization.

* You are prompted to authenticate with `sparklr`.

* Then `sparklr` will ask you if you authorize `tonr` to access your
  photos.
  
* If you say "yes" then your browser will be redirected back to `tonr`
  and this time the correct authorization is present, so you will be
  able to see your photos.

## How to build the WAR files

Use Maven (2.2.1 works) and, from this directory do 

    $ mvn package

and then look in `*/{sparklr,tonr}/target` for the war files.  Deploy
them with context roots `{/sparklr,/tonr}` (for OAuth 1) and
`{/sparklr2,/tonr2}` (for OAuth 2) respectively in your favourite web
container, and fire up the `tonr` app to see the two working together.

## How to deploy in Eclipse (e.g. STS)

To deploy the apps in Eclipse you will need the Maven plugin (`m2e`)
and the Web Tools Project (WTP) plugins.  If you have SpringSource
Toolsuite (STS) you should already have those, aso you can deploy the
apps very simply.  (Update the WTP plugin to at least version 0.12 at
http://download.eclipse.org/technology/m2e/releases if you have an older
one, or the context roots for the apps will be wrong.)

* Ensure the Spring Security OAuth dependencies are available locally
first.  You can do this by importing all projects, or by building on
the command line before importing the samples (using `mvn install`).

* Import the projects:

        File->Import...->Maven->Existing Maven Projects->Next

  browse to the parent directory containing all the
  samples and press `Finish`.
  
* Wait for the projects to build, and then just right click on the two
  webapps (`sparklr` and `tonr` or `sparklr2` and `tonr2`) and `Run
  As` then `Run on Server`.  If you have a server set up already
  (e.g. tcServer is probably there out of teh box) select that, or
  else create a new server, and follow the dialogues.
  
  If you have a server instance set up you can also drag and drop the
  apps to a server instance (e.g. tcServer or Tomcat) in the `Servers`
  View.

* Visit the `tonr` app in a browser
  (e.g. [http://localhost:8080/tonr2](http://localhost:8080/tonr2)).
