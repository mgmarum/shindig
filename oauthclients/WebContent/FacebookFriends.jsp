<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ page import="java.util.*" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Your Friends</title>
</head>
<body>
    <h1>Welcome to the most ADVANCED Facebook client EVER!!!</H1>
	<%
		if (request.getAttribute("friends") == null) {
			%><form action="FacebookClient/friends" method="GET">
				<input type="submit" value="Get Facebook Friends!">
			</form><%
		} else {
			List<String> friends = (List<String>)request.getAttribute("friends");
			%>You have <%= friends.size() %> friends!
			<ul><%
			for (String friend : friends) {
				%><li><%=friend%></li><%
			}
			%></ul><%
		}
	%>
</body>
</html>