<%@ page contentType="application/xhtml+xml" pageEncoding="UTF-8"%>
<%@ include file="/WEB-INF/jspf/taglibs.jspf" %>
<%@ include file="/WEB-INF/jspf/header.jspf" %>

<h1>Sparklr</h1>

<div id="content">
    <c:if test="${not empty param.authentication_error}">
        <h1>Woops!</h1>

        <p class="error">Your login attempt was not successful.</p>
    </c:if>
    <c:if test="${not empty param.authorization_error}">
        <h1>Woops!</h1>

        <p class="error">You are not permitted to access that resource.</p>
    </c:if>


    <h2>Login</h2>

    <p>We've got a grand total of 2 users: marissa and paul. Go ahead
        and log in. Marissa's password is "koala" and Paul's password is "emu".
    </p>

    <form id="loginForm" name="loginForm" action="<c:url value='/login.do'/>" method="post">
        <p><label>Username: <input type='text' name='j_username' value="marissa" /></label></p>
        <p><label>Password: <input type='text' name='j_password' value="koala" /></label></p>

        <p><input name="login" value="Login" type="submit" /></p>
    </form>
</div>

<%@ include file="/WEB-INF/jspf/footer.jspf" %>
