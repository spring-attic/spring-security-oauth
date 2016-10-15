[![Build Status](https://travis-ci.org/spring-projects/spring-security-oauth.svg?branch=master)](https://travis-ci.org/spring-projects/spring-security-oauth) 

This project provides support for using Spring Security with OAuth
(1a) and OAuth2.  It provides features for implementing both consumers
and providers of these protocols using standard Spring and Spring
Security programming models and configuration idioms.

# Code of Conduct
This project adheres to the Contributor Covenant [code of conduct](CODE_OF_CONDUCT.adoc).
By participating, you  are expected to uphold this code. Please report unacceptable behavior to spring-code-of-conduct@pivotal.io.

# Getting Started

[Download](https://github.com/spring-projects/spring-security-oauth/tags)
or clone from
[GIT](https://github.com/spring-projects/spring-security-oauth) and then
use Maven (3.0.\*) and Java (1.6 or better):

    $ git clone ...
    $ mvn install -P bootstrap

Use the `bootstrap` profile only the first time - it enables some
repositories that can't be exposed in the poms by default. You may
find it useful to add this profile to your local `settings.xml`.

Some tests require locally running instance or [Redis](http://redis.io/). To set it up
follow [Redis quickstart](http://redis.io/topics/quickstart) or for ease use
[Docker](https://www.docker.com/)ized instance by running ```docker run -dp 6379:6379 redis```.

SpringSource ToolSuite users (or Eclipse users with the latest
m2eclipse plugin) can import the projects as existing Maven projects.

Spring Security OAuth is released under the terms of the Apache
Software License Version 2.0 (see license.txt).

## Samples

Samples and integration tests are in [a subdirectory](samples).  There
is a separate README there for orientation and information.  Once you
have installed the artifacts locally (as per the getting started
instructions above) you should be able to

    $ cd samples/oauth2/tonr
    $ mvn tomcat7:run
	
and visit the app in your browser at [http://localhost:8080/tonr2/](http://localhost:8080/tonr2/)
to check that it works.  (This is for the OAuth 2.0 sample, for the
OAuth 1.0a sample just remove the "2" from the directory path.) Integration tests
require slightly different settings for Tomcat so you need to add a profile:

    $ cd samples/oauth2/tonr
    $ mvn integration-test -P integration

## Changelog

Lists of issues addressed per release can be found in [github](https://github.com/spring-projects/spring-security-oauth/milestones) (older releases are in
[JIRA](https://jira.spring.io/browse/SECOAUTH/?selectedTab=com.atlassian.jira.jira-projects-plugin:versions-panel)).

## Additional Resources

* [Spring Security OAuth User Guide](http://projects.spring.io/spring-security-oauth/docs/Home.html)
* [Spring Security OAuth Source](http://github.com/spring-projects/spring-security-oauth)
* [Stackoverflow](http://stackoverflow.com/questions/tagged/spring-security+spring+oauth)

# Contributing to Spring Security OAuth

Here are some ways for you to get involved in the community:

* Get involved with the Spring community on the Spring Community Forums.  Please help out on the
  [forum](http://forum.springsource.org/forumdisplay.php?f=79) by responding to questions and joining the debate.
* Create [github issues](https://github.com/spring-projects/spring-security-oauth/issues) for bugs and new features and comment and
  vote on the ones that you are interested in.
* Github is for social coding: if you want to write code, we encourage contributions through pull requests from
  [forks of this repository](http://help.github.com/forking/).  If you want to contribute code this way, please
  reference a github issue as well covering the specific issue you are addressing.
* Watch for upcoming articles on Spring by [subscribing](http://www.springsource.org/node/feed) to springframework.org

Before we accept a non-trivial patch or pull request we will need you to sign the
[contributor's agreement](https://support.springsource.com/spring_committer_signup).
Signing the contributor's agreement does not grant anyone commit rights to the main repository, but it does mean that we
can accept your contributions, and you will get an author credit if we do.  Active contributors might be asked to join
the core team, and given the ability to merge pull requests.

## Code Conventions and Housekeeping

None of these is essential for a pull request, but they will all help.  They can also be added after the original pull
request but before a merge.

* Use the Spring Framework code format conventions. Import `eclipse-code-formatter.xml` from the root of the project
  if you are using Eclipse. If using IntelliJ, copy `spring-intellij-code-style.xml` to `~/.IntelliJIdea*/config/codestyles`
  and select spring-intellij-code-style from Settings -> Code Styles.
* Make sure all new .java files have a simple Javadoc class comment with at least an @author tag identifying you, and
  preferably at least a paragraph on what the class is for.
* Add the ASF license header comment to all new .java files (copy from existing files in the project)
* Add yourself as an @author to the .java files that you modify substantially (more than cosmetic changes).
* Add some Javadocs and, if you change the namespace, some XSD doc elements.
* A few unit tests would help a lot as well - someone has to do it.
* If no-one else is using your branch, please rebase it against the current master (or other target branch in the main project).
