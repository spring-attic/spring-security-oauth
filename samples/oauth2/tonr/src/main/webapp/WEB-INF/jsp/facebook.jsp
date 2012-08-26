<%@ page contentType="application/xhtml+xml" pageEncoding="UTF-8" %>
<%@ include file="/WEB-INF/jspf/taglibs.jspf" %>
<%@ include file="/WEB-INF/jspf/header.jspf" %>

<div id="container">

    <c:set var="selected" value="facebook" scope="page" />
    <%@ include file="/WEB-INF/jspf/menu.jspf" %>

    <div id="content">
        <h1>Your Facebook Friends:</h1>

        <ul>
            <c:forEach var="friendName" items="${friends}">
                <li><c:out value="${friendName}" /></li>
            </c:forEach>
        </ul>
    </div>
</div>

<%@ include file="/WEB-INF/jspf/footer.jspf" %>