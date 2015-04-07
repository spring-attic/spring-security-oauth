---
title: Docs
layout: default
home: ../
---


# Downloads

You can download source code bundles from [Github], or clone the repository using git.  OAuth for Spring Security is a Maven-based project.

* groupId: `org.springframework.security.oauth`
* artifactId: `spring-security-oauth` for OAuth 1.0a and `spring-security-oauth2` for OAuth 2.0

To download the jars, just look in the [Maven repository][mavenrepo].

Full releases go in Maven [central], and in the SpringSource repository but milestones and snapshots go only in the SpringSource respository.  For milestones:

    <repository>
        <id>spring-milestone</id>
        <name>Spring Maven MILESTONE Repository</name>
        <url>http://maven.springframework.org/milestone</url>
    </repository>

and for snapshots:

    <repository>
        <id>spring-snnapshot</id>
        <name>Spring Maven SNAPSHOT Repository</name>
        <url>http://maven.springframework.org/snapshot</url>
    </repository>

[mavenrepo]: http://shrub.appspot.com/maven.springframework.org/release/org/springframework/security/oauth/spring-security-oauth/
[central]: http://repo1.maven.org/maven2/org/springframework/security/oauth/spring-security-oauth/
[Github]: https://github.com/spring-projects/spring-security-oauth
