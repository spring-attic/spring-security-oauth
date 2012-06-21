<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
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
      <li><a href="<c:url value="/sparklr/photos"/>" class="selected">sparklr pics</a></li>
      <li><a href="<c:url value="/facebook/info"/>">facebook friends</a></li>
    </ul>

  <div id="content">
    <h1>Your Sparklr Photos</h1>
    
    <ul id="picturelist">
      <c:forEach var="sparklrPhotoId" items="${photoIds}">
        <li><img src="<c:url value="/sparklr/photos/${sparklrPhotoId}"/>"/></li>
      </c:forEach>
    </ul>
  </div>
</div>
</body>
</html>