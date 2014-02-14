<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Sparklr</title>
<link type="text/css" rel="stylesheet"
	href="../webjars/bootstrap/3.0.3/css/bootstrap.min.css" />
<script type="text/javascript" src="../webjars/jquery/1.9.0/jquery.min.js"></script>
<script type="text/javascript"
	src="../webjars/bootstrap/3.0.3/js/bootstrap.min.js"></script>
</head>

<body>

	<div class="container">

		<h1>Sparklr OAuth2 Error</h1>

		<p>
			<c:out value="${message}" />
			(
			<c:out value="${error.summary}" />
			)
		</p>
		<p>Please go back to your client application and try again, or
			contact the owner and ask for support</p>

		<div class="footer">
			Sample application for <a
				href="http://github.com/spring-projects/spring-security-oauth"
				target="_blank">Spring Security OAuth</a>
		</div>


	</div>

</body>
</html>
