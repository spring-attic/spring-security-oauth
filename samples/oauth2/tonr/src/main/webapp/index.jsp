<%@ page contentType="application/xhtml+xml" pageEncoding="UTF-8" %>
<%@ include file="/WEB-INF/jspf/taglibs.jspf" %>
<%@ include file="/WEB-INF/jspf/header.jspf" %>

<div id="container">

    <c:set var="selected" value="home" scope="page" />
    <%@ include file="/WEB-INF/jspf/menu.jspf" %>

    <div id="content">
        <h1>Welcome to Tonr.com!</h1>

        <p>This is a website that will allow you to print your photos that you've uploaded to <a href="http://localhost:8080/sparklr/">sparklr.com</a>!
            And since this site uses <a href="http://oauth.net">OAuth</a> to access your photos, we will never ask you
            for your Sparklr credentials.
        </p>

        <p>Tonr.com has only two users: "marissa" and "sam".  The password for "marissa" is password is "wombat" and for "sam" is password is "kangaroo".</p>

        <authz:authorize ifNotGranted="ROLE_USER">
            <p><a href="<c:url value='login.jsp'/>">Login to Tonr</a></p>
        </authz:authorize>

        <authz:authorize ifAllGranted="ROLE_USER">
            <p><a href="<c:url value='/sparklr/photos'/>">View my Sparklr photos</a></p>
        </authz:authorize>

    </div>
</div>

<%@ include file="/WEB-INF/jspf/footer.jspf" %>