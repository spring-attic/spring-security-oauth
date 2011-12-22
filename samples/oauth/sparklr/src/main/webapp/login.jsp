<%@ page import="org.springframework.security.core.AuthenticationException" %>
<%@ page import="org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter" %>
<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jstl/core" %>
<authz:authorize ifAllGranted="ROLE_USER">
  <c:redirect url="index.jsp"/>
</authz:authorize>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1"/>
  <title>Sparklr</title>
  <link type="text/css" rel="stylesheet" href="<c:url value="/style.css"/>"/>
</head>

<body>

  <h1>Sparklr</h1>

  <div id="content">
    <c:if test="${!empty sessionScope.SPRING_SECURITY_LAST_EXCEPTION}">
      <div class="error">
		<h2>Woops!</h2>

      	<p>Your login attempt was not successful. (<%= ((AuthenticationException) session.getAttribute(AbstractAuthenticationProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY)).getMessage() %>)</p>
      </div>
    </c:if>
    <c:remove scope="session" var="SPRING_SECURITY_LAST_EXCEPTION"/>

    <authz:authorize ifNotGranted="ROLE_USER">
      <h2>Login</h2>

      <p>We've got a grand total of 2 users: marissa and paul. Go ahead and log in. Marissa's password is "koala" and Paul's password is "emu".</p>
      <form action="<c:url value="/login.do"/>" method="post">
        <p><label>Username: <input type='text' name='j_username' value="marissa"></label></p>
        <p><label>Password: <input type='text' name='j_password' value="koala"></label></p>
        
        <p><input name="login" value="Login" type="submit"></p>
      </form>
    </authz:authorize>
  </div>

  <div id="footer">Design by <a href="http://www.pyserwebdesigns.com" target="_blank">Pyser Web Designs</a></div>


</body>
</html>
