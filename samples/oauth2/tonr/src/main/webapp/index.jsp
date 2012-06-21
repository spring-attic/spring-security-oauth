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
      <li><a href="<c:url value="/index.jsp"/>" class="selected">home</a></li>
      <authz:authorize ifNotGranted="ROLE_USER">
        <li><a href="<c:url value="/login.jsp"/>">login</a></li>
      </authz:authorize>
      <li><a href="<c:url value="/sparklr/photos"/>">sparklr pics</a></li>
      <li><a href="<c:url value="/facebook/info"/>">facebook friends</a></li>
    </ul>

  <div id="content">
    <h1>Welcome to Tonr.com!</h1>
    
    <p>This is a website that will allow you to print your photos that you've uploaded to <a href="http://localhost:8080/sparklr/">sparklr.com</a>!
      And since this site uses <a href="http://oauth.net">OAuth</a> to access your photos, we will never ask you
      for your Sparklr credentials.</p>

    <p>Tonr.com has only two users: "marissa" and "sam".  The password for "marissa" is password is "wombat" and for "sam" is password is "kangaroo".</p>

    <authz:authorize ifNotGranted="ROLE_USER">
      <p><a href="<c:url value="login.jsp"/>">Login to Tonr</a></p>
    </authz:authorize>
    <authz:authorize ifAllGranted="ROLE_USER">
      <p><a href="<c:url value="/sparklr/photos"/>">View my Sparklr photos</a></p>
    </authz:authorize>

    <p class="footer">Courtesy <a href="http://www.openwebdesign.org">Open Web Design</a> Thanks to <a href="http://www.dubaiapartments.biz/">Dubai Hotels</a></p>
  </div>
</div>
</body>
</html>