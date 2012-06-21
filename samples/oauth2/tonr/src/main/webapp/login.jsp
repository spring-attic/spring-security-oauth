<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<link href="<c:url value="/main.css"/>" rel="stylesheet" type="text/css" />
<title>tonr</title>
</head>
<body>
	<div id="container">

		<ul id="mainlinks">
			<li><a href="<c:url value="/index.jsp"/>">home</a></li>
			<li><a href="<c:url value="/login.jsp"/>" class="selected">login</a></li>
			<li><a href="<c:url value="/sparklr/photos"/>">sparklr pics</a></li>
			<li><a href="<c:url value="/facebook/info"/>">facebook
					friends</a></li>
		</ul>

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
				"kangaroo".</p>

			<form action="<c:url value="/login.do"/>" method="post">
				<p>
					<label>Username: <input type='text' name='j_username'
						value="marissa"/></label>
				</p>
				<p>
					<label>Password: <input type='text' name='j_password'
						value="wombat"/></label>
				</p>

				<p>
					<input name="login" value="Login" type="submit"/>
				</p>
			</form>

			<p class="footer">
				Courtesy <a href="http://www.openwebdesign.org">Open Web Design</a>
				Thanks to <a href="http://www.dubaiapartments.biz/">Dubai Hotels</a>
			</p>
		</div>
	</div>
</body>
</html>