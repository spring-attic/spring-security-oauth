<%@ page contentType="application/xhtml+xml" pageEncoding="UTF-8" %>
<%@ include file="/WEB-INF/jspf/taglibs.jspf" %>
<%@ include file="/WEB-INF/jspf/header.jspf" %>

<div id="container">

    <c:set var="selected" value="photos" scope="page" />
    <%@ include file="/WEB-INF/jspf/menu.jspf" %>

    <div id="content">
        <h1>Your Sparklr Photos</h1>

        <ul id="picturelist">
            <c:forEach var="sparklrPhotoId" items="${photoIds}">
                <li><img src="<c:url value='/sparklr/photos/${sparklrPhotoId}'/>" /></li>
            </c:forEach>
        </ul>
    </div>
</div>

<%@ include file="/WEB-INF/jspf/footer.jspf" %>