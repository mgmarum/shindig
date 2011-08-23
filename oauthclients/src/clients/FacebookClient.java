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
 * Facebook OAuth 2.0 client.
 */
public class FacebookClient extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	private static String appId = "248416068515117";
	private static String appSecret = "02db45b8507105fa1e6e3740cf7a1e59";
	private static String accessToken = null;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public FacebookClient() {
        super();
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("doGet()");
		
		String path = request.getPathInfo();
		if (path == null || path.isEmpty()) {	// serve JSP page
			System.out.println("base path received, forwarding to JSP");
			this.getServletContext().getRequestDispatcher("/FacebookFriends.jsp").forward(request, response);
		} else if (path.endsWith("/friends")) {
			System.out.println("Friends requested");
			List<String> friends = null;
			if (accessToken == null || (friends = getFacebookFriends()) == null) { // handle invalid access token
				System.out.println("Invalid access token...");
				if (request.getParameterMap().containsKey("code")) {	// Have authorization code
					System.out.println("Have authorization code, retrieving access token...");
					accessToken = getAccessToken(request.getParameter("code"));
					System.out.println("Successfully received access token: " + accessToken);
					this.getServletContext().getRequestDispatcher("/FacebookClient/friends").forward(request, response);
				} else {	// Need to get authorization code
					System.out.println("Requesting authorization code...");
					response.sendRedirect("https://www.facebook.com/dialog/oauth?client_id=" + appId + "&redirect_uri=http://localhost:8080/oauthclients/FacebookClient/friends");
				}
			} else {
				System.out.println("Successfully retrieved friends");
				request.setAttribute("friends", friends);
				this.getServletContext().getRequestDispatcher("/FacebookClient").forward(request, response);
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
		params.put("redirect_uri", "http://localhost:8080/oauthclients/FacebookClient/friends");
		params.put("client_secret", appSecret);
		params.put("code", authCode);
		Response resp = connection.get("https://graph.facebook.com/oauth/access_token", null, params);
		if (resp.getStatusCode() != 200) {
			throw new RuntimeException("OMG UR REJETCED!!1");
		} else {
			return resp.getBody().substring("access_token=".length(), resp.getBody().indexOf('&'));
		}
	}
	
	/**
	 * Get list of Facebook friends.
	 */
	private List<String> getFacebookFriends() {
		HttpConnection connection = new HttpConnection();
		Map<String, String> params = new HashMap<String, String>();
		params.put("access_token", accessToken);
		System.out.println("Using access token to retrieve friends: " + accessToken);
		Response resp = connection.get("https://graph.facebook.com/me/friends", null, params);
		if (resp.getStatusCode() != 200) {
			System.out.println(resp.toString());
			return null;
		}
		try {
			List<String> friends = new ArrayList<String>();
			JSONObject respJson = new JSONObject(resp.getBody());
			JSONArray friendsJson = respJson.getJSONArray("data");
			for (int i = 0; i < friendsJson.length(); i++) {
				friends.add(friendsJson.getJSONObject(i).getString("name"));
			}
			return friends;
		} catch (JSONException e) {
			e.printStackTrace();
			throw new RuntimeException("things blewd up");
		}
	}
}
