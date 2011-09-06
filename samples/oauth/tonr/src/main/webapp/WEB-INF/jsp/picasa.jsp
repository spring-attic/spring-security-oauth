<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jstl/core" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <link href="<c:url value="/main.css"/>" rel="stylesheet" type="text/css"/>
  <title>tonr</title>
</head>
<body>
<div id="container">

    <ul id="mainlinks">
      <li><a href="<c:url value="/index.jsp"/>">home</a></li>
      <authz:authorize ifNotGranted="ROLE_USER">
        <li><a href="<c:url value="/login.jsp"/>">login</a></li>
      </authz:authorize>
      <li><a href="<c:url value="/sparklr/photos"/>">sparklr pics</a></li>
      <li><a href="<c:url value="/google/picasa"/>" class="selected">picasa pics</a></li>
    </ul>

  <div id="content">
    <h1>Your Picasa Photos</h1>
    
    <ul id="picturelist">
      <c:forEach var="photoUrl" items="${photoUrls}">
        <li><img src="<c:out value="${photoUrl}"/>"/></li>
        <li><c:out value="${photoUrl}"/></li>
      </c:forEach>
    </ul>
  </div>
</div>
</body>
</html>