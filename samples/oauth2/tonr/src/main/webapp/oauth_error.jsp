<%@ page import="java.io.PrintWriter" %>
<%@ page import="java.io.StringWriter" %>

<%@ page contentType="application/xhtml+xml" pageEncoding="UTF-8" %>
<%@ include file="/WEB-INF/jspf/taglibs.jspf" %>
<%@ include file="/WEB-INF/jspf/header.jspf" %>

<div id="container">

    <ul id="mainlinks">
        <li><a href="<c:url value='/index.jsp'/>">home</a></li>

        <authz:authorize ifNotGranted="ROLE_USER">
            <li><a href="<c:url value='/login.jsp'/>">login</a></li>
        </authz:authorize>

        <li><a href="<c:url value='/sparklr/photos'/>">sparklr pics</a></li>
        <li><a href="<c:url value='/facebook/info'/>">facebook friends</a></li>
    </ul>

</div>

<%@ include file="/WEB-INF/jspf/footer.jspf" %>