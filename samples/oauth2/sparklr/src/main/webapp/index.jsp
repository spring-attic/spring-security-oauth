<%@ taglib prefix="authz"
	uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>Sparklr</title>
<link type="text/css" rel="stylesheet"
	href="webjars/bootstrap/3.0.3/css/bootstrap.min.css" />
<script type="text/javascript" src="webjars/jquery/1.9.0/jquery.min.js"></script>
<script type="text/javascript"
	src="webjars/bootstrap/3.0.3/js/bootstrap.min.js"></script>

<authz:authorize ifAllGranted="ROLE_USER">
	<script type='text/javascript'>
		function pictureDisplay(json) {
			for (var i = 0; i < json.photos.length; i++) {
				var photo = json.photos[i];
				document
						.write('<img src="photos/' + photo.id + '" alt="' + photo.name + '">');
			}
		}
	</script>
</authz:authorize>
</head>
<body>

	<div class="container">

		<h1>Sparklr</h1>

		<h2>Home</h2>

		<p>This is a great site to store and view your photos.
			Unfortunately, we don't have any services for printing your photos.
			For that, you'll have to go to Tonr.</p>

		<authz:authorize ifAllGranted="ROLE_USER">
			<div class="form-horizontal">
				<form action="<c:url value="/logout.do"/>" role="form">
					<button class="btn btn-primary" type="submit">Logout</button>
				</form>
			</div>

			<h2>Your Photos</h2>

			<p>
				<script type='text/javascript'
					src='photos?callback=pictureDisplay&format=json'></script>
			</p>
		</authz:authorize>

		<div class="footer">
			Sample application for <a
				href="http://github.com/spring-projects/spring-security-oauth"
				target="_blank">Spring Security OAuth</a>
		</div>

	</div>

</body>
</html>
