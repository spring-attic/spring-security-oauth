---
title: Docs
layout: default
home: ../
---

### Deprecation Notice

The Spring Security OAuth project is deprecated. The latest OAuth 2.0 support is provided by Spring Security. See the [OAuth 2.0 Migration Guide](https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide) for further details.

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
        <url>https://maven.springframework.org/milestone</url>
    </repository>

and for snapshots:

    <repository>
        <id>spring-snnapshot</id>
        <name>Spring Maven SNAPSHOT Repository</name>
        <url>https://maven.springframework.org/snapshot</url>
    </repository>

[mavenrepo]: https://shrub.appspot.com/maven.springframework.org/release/org/springframework/security/oauth/spring-security-oauth/
[central]: https://repo1.maven.org/maven2/org/springframework/security/oauth/spring-security-oauth/
[Github]: https://github.com/spring-projects/spring-security-oauth
