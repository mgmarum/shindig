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
 * Performs the Auth 2.0 implicit grant flow.
 * 
 * NOTE: This servlet mock's the implicit grant flow from the SERVER'S
 * perspective.  This is not what a real client would ever look like.
 */
public class ImplicitClient extends HttpServlet {

	private static final long serialVersionUID = -629835685914414480L;
	private static final String clientId = "advancedImplicitClient";
	private static final String redirectUri = "http://localhost:8080/oauthclients/ImplicitClient";
	private String accessToken = null;
	
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		System.out.println("ImplicitClient.doGet()");
		request.setAttribute("client", "ImplicitClient");
		
		// Get access token/friends if requested
		if (request.getPathInfo() != null && request.getPathInfo().endsWith("/friends")) {
			if (accessToken == null) {
				accessToken = getAccessToken();
			}
			List<String> friends = getOpenSocialFriends();
			if (friends != null) {
				request.setAttribute("friends", friends);
			}
		}
		
		// Forward to friends servlet
		this.getServletContext().getRequestDispatcher("/OpenSocialFriends.jsp").forward(request, response);
	}
	
	private String getAccessToken() {
		HttpConnection connection = new HttpConnection();
		Map<String, String> params = new HashMap<String, String>();
		params.put("response_type", "token");
		params.put("client_id", clientId);
		params.put("redirect_uri", redirectUri);
		System.out.println("Requesting access token");
		Response resp = connection.get("http://localhost:8080/oauth2/authorize", null, params);
		System.out.println("Response:\n" + resp.toString());
		if (resp.getStatusCode() == 302) {
			return parseAccessTokenFromUri(resp.getHeaders().get("Location"));
		} else {
			throw new RuntimeException("Did not receive redirect as expected");
		}
	}
	
	private String parseAccessTokenFromUri(String uri) {
		return "abc123";
	}
	
	private List<String> getOpenSocialFriends() {
		HttpConnection connection = new HttpConnection();
		Map<String, String> params = new HashMap<String, String>();
		params.put("access_token", accessToken);
		System.out.println("Using access token to retrieve friends: " + accessToken);
		Response resp = connection.get("http://localhost:8080/social/rest/people/john.doe/@friends/", null, params);
		System.out.println("Response:\n" + resp.toString());
		if (resp.getStatusCode() != 200) {
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
