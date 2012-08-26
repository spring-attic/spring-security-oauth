<%@ page contentType="application/xhtml+xml" pageEncoding="UTF-8" %>
<%@ include file="/WEB-INF/jspf/taglibs.jspf" %>
<%@ include file="/WEB-INF/jspf/header.jspf" %>

<div id="container">

    <c:set var="selected" value="login" scope="page" />
    <%@ include file="/WEB-INF/jspf/menu.jspf" %>

    <div id="content">
        <c:if test="${not empty param.authentication_error}">
            <h1>Woops!</h1>

            <p class="error">Your login attempt was not successful.</p>
        </c:if>

        <c:if test="${not empty param.authorization_error}">
            <h1>Woops!</h1>

            <p class="error">You are not permitted to access that resource.</p>
        </c:if>

        <h1>Login</h1>

        <p>Tonr.com has only two users: "marissa" and "sam". The password
            for "marissa" is password is "wombat" and for "sam" is password is
            "kangaroo".
        </p>

        <form action="<c:url value='/login.do'/>" method="post">
            <p><label>Username: <input type='text' name='j_username' value="marissa"/></label></p>
            <p><label>Password: <input type='text' name='j_password' value="wombat" /></label></p>

            <p><input name="login" value="Login" type="submit" /></p>
        </form>
    </div>
</div>

<%@ include file="/WEB-INF/jspf/footer.jspf" %>