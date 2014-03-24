<%@ taglib prefix="authz"
	uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jstl/core"%>
<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<c:url value="/" var="base" />
<link type="text/css" rel="stylesheet"
	href="${base}webjars/bootstrap/3.0.3/css/bootstrap.min.css" />
<script type="text/javascript"
	src="${base}webjars/jquery/1.9.0/jquery.min.js"></script>
<script type="text/javascript"
	src="${base}webjars/bootstrap/3.0.3/js/bootstrap.min.js"></script>
</head>
<body>
	<div id="navbar" class="navbar navbar-default" role="navigation">
		<div class="navbar-header">
			<button type="button" class="navbar-toggle" data-toggle="collapse"
				data-target=".navbar-collapse">
				<span class="icon-bar"></span> <span class="icon-bar"></span> <span
					class="icon-bar"></span>
			</button>
			<a class="navbar-brand"
				href="https://github.com/spring-projects/spring-security-oauth">
				Tonr</a>
		</div>
		<div class="navbar-collapse collapse">
			<ul class="nav navbar-nav">
				<li><a href="${base}index.jsp">home</a></li>
				<li><a href="${base}sparklr/photos">sparklr pics</a></li>
				<li><a href="${base}facebook/info">facebook friends</a></li>
			</ul>
		</div>
	</div>
	<div class="container"></div>
</body>
</html>