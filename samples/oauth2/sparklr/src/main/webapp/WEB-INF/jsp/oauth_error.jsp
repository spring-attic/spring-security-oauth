<%@page contentType="application/xhtml+xml" pageEncoding="UTF-8"%>
<%@ include file="/WEB-INF/jspf/taglibs.jspf" %>
<%@ include file="/WEB-INF/jspf/header.jspf" %>

<h1>Sparklr OAuth2 Error</h1>

<div id="content">
    <p><c:out value="${message}" /> (<c:out value="${error.summary}" />)</p>
    
    <p>Please go back to your client application and try again, or contact the owner and ask for support</p>
</div>

<%@ include file="/WEB-INF/jspf/footer.jspf" %>
