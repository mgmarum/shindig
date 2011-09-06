package clients;


import http.HttpConnection;
import http.Response;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * OpenSocial OAuth 2.0 client.
 */
public class AuthorizationCodeClient extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private static String appId = "advancedAuthorizationCodeClient";
	private static String appSecret = "advancedAuthorizationCodeClient_secret";
	private static String accessToken = null;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public AuthorizationCodeClient() {
        super();
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("doGet()");
		request.setAttribute("client", "AuthorizationCodeClient");
		
		String path = request.getPathInfo();
		if (path == null || path.isEmpty()) {	// serve JSP page
			System.out.println("base path received, forwarding to JSP");
			this.getServletContext().getRequestDispatcher("/OpenSocialFriends.jsp").forward(request, response);
		} else if (path.endsWith("/friends")) {
			System.out.println("Friends requested");
			List<String> friends = null;
			if (accessToken == null || (friends = getOpenSocialFriends()) == null) { // handle invalid access token
				System.out.println("Invalid access token...");
				if (request.getParameterMap().containsKey("code")) {	// Have authorization code
					System.out.println("Have authorization code, retrieving access token...");
					System.out.println("authorization code: " + request.getParameter("code"));
					accessToken = getAccessToken(request.getParameter("code"));
					System.out.println("Successfully received access token: " + accessToken);
					this.getServletContext().getRequestDispatcher("/AuthorizationCodeClient/friends").forward(request, response);
				} else {	// Need to get authorization code
					System.out.println("Requesting authorization code...");
					System.out.println("http://localhost:8080/oauth2/authorize?client_id=" + appId + "&client_secret=" + appSecret + "&response_type=code&redirect_uri=http://localhost:8080/oauthclients/AuthorizationCodeClient/friends");
					response.sendRedirect("http://localhost:8080/oauth2/authorize?client_id=" + appId + "&client_secret=" + appSecret + "&response_type=code&redirect_uri=http://localhost:8080/oauthclients/AuthorizationCodeClient/friends");
				}
			} else {
				System.out.println("Successfully retrieved friends");
				request.setAttribute("friends", friends);
				this.getServletContext().getRequestDispatcher("/AuthorizationCodeClient").forward(request, response);
			}
		}
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("doPost()");
	}
	
	/**
	 * Retrieves an access token.
	 */
	private String getAccessToken(String authCode) {
		HttpConnection connection = new HttpConnection();
		Map<String, String> params = new HashMap<String, String>();
		params.put("client_id", appId);
		params.put("redirect_uri", "http://localhost:8080/oauthclients/AuthorizationCodeClient/friends");
		params.put("client_secret", appSecret);
		params.put("code", authCode);
		params.put("grant_type", "authorization_code");
    Map<String, String> headers = new HashMap<String, String>();
    headers.put("Content-Type", "application/x-www-form-urlencoded");
		Response resp = connection.post("http://localhost:8080/oauth2/token", headers, null, HttpConnection.convertQueryString(params));
		System.out.println("Done posting, response:");
		System.out.println(resp.toString());
		if (resp.getStatusCode() != 200) {
			throw new RuntimeException("OMG UR REJETCED!!1");
		} else {
			try {
				JSONObject respJson = new JSONObject(resp.getBody());
				return respJson.getString("access_token");
			} catch (JSONException e) {
				e.printStackTrace();
				return null;
			}
		}
	}
	
	/**
	 * Get list of OpenSocial friends.
	 */
	private List<String> getOpenSocialFriends() {
		HttpConnection connection = new HttpConnection();
		Map<String, String> params = new HashMap<String, String>();
		params.put("access_token", accessToken);
		System.out.println("Using access token to retrieve friends: " + accessToken);
		Response resp = connection.get("http://localhost:8080/social/rest/people/john.doe/@friends/", null, params);
		if (resp.getStatusCode() != 200) {
			System.out.println(resp.toString());
			return null;
		}
		try {
			List<String> friends = new ArrayList<String>();
			JSONObject respJson = new JSONObject(resp.getBody());
			JSONArray friendsJson = respJson.getJSONArray("entry");
			for (int i = 0; i < friendsJson.length(); i++) {
				friends.add(friendsJson.getJSONObject(i).getJSONObject("name").getString("formatted"));
			}
			return friends;
		} catch (JSONException e) {
			e.printStackTrace();
			throw new RuntimeException("things blewd up");
		}
	}
}
