<%@ page import="org.springframework.security.core.AuthenticationException" %>
<%@ page import="org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter" %>
<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jstl/core" %>
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

        <p>Access could not be granted. (<%= ((AuthenticationException) session.getAttribute(AbstractAuthenticationProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY)).getMessage() %>)</p>
      </div>
    </c:if>
    <c:remove scope="session" var="SPRING_SECURITY_LAST_EXCEPTION"/>

    <authz:authorize ifAllGranted="ROLE_USER">
      <h2>Please Confirm</h2>

      <p>You hereby authorize "<c:out value="${consumer.consumerName}"/>" to access the following resource:</p>

      <ul>
          <li><c:out value="${consumer.resourceName}"/> &mdash; <c:out value="${consumer.resourceDescription}"/></li>
      </ul>

      <form action="<c:url value="/oauth/authorize"/>" method="post">
        <input name="requestToken" value="<c:out value="${oauth_token}"/>" type="hidden"/>
        <c:if test="${!empty oauth_callback}">
        <input name="callbackURL" value="<c:out value="${oauth_callback}"/>" type="hidden"/>
        </c:if>
        <label><input name="authorize" value="Authorize" type="submit"></label>
      </form>
    </authz:authorize>
  </div>

  <div id="footer">Design by <a href="http://www.pyserwebdesigns.com" target="_blank">Pyser Web Designs</a></div>


</body>
</html>
