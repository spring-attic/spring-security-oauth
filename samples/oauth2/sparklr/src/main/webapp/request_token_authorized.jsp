<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
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
    <h2>Home</h2>

    <p>You have successfully authorized the request for a protected resource.</p>
  </div>

  <div id="footer">Sample application for <a href="http://github.com/SpringSource/spring-security-oauth" target="_blank">Spring Security OAuth</a></div>


</body>
</html>
