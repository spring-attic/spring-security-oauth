<%@ page contentType="text/html" pageEncoding="UTF-8" %>
<%@ include file="/WEB-INF/jspf/taglibs.jspf" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <meta http-equiv="Content-Language" content="en" />
        <meta name="robots" content="noindex,nofollow" />
        <link type="text/css" rel="stylesheet"
              href="<c:url value='/styles/main.css'/>" />

        <authz:authorize ifAllGranted="ROLE_USER">
            <script type="text/javascript">
            //<![CDATA[
                function pictureDisplay(json) {
                    for (var i = 0; i < json.photos.length; i++) {
                        var photo = json.photos[i];
                        document.write('<img src="photos/' + photo.id + '" alt="' + photo.name + '">');
                    }
                }
            //]]>
            </script>
        </authz:authorize>

        <title>Sparkl – Sample OAuth2 Resource &amp; Authorization Server</title>
    </head>

    <body>
        <h1>Sparklr</h1>

        <div id="content">
            <h2>Home</h2>

            <p>This is a great site to store and view your photos. Unfortunately, we don't have any services
                for printing your photos.  For that, you'll have to go to Tonr.</p>

            <authz:authorize ifNotGranted="ROLE_USER">
                <h2>Login</h2>

                <form id="loginForm" name="loginForm" action="<c:url value='/login.do'/>" method="post">
                    <p><label>Username: <input type='text' name='j_username' value="marissa" /></label></p>
                    <p><label>Password: <input type='text' name='j_password' value="koala" /></label></p>

                    <p><input name="login" value="Login" type="submit" /></p>
                </form>
            </authz:authorize>

            <authz:authorize ifAllGranted="ROLE_USER">
                <div style="text-align: center">
                    <form action="<c:url value='/logout.do'/>">
                        <input type="submit" value="Logout" />
                    </form>
                </div>

                <h2>Your Photos</h2>

                <p>
                    <script type="text/javascript" src="photos?callback=pictureDisplay&amp;format=json"></script>
                </p>
            </authz:authorize>
        </div>

<%@ include file="/WEB-INF/jspf/footer.jspf" %>
