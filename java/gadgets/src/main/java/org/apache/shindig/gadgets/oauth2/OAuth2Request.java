package org.apache.shindig.gadgets.oauth2;

import java.util.List;

import net.oauth.OAuth.Parameter;

import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.oauth.OAuthRequestException;

/**
 * Implements both signed fetch and full OAuth for gadgets, as well as a
 * combination of the two that is necessary to build OAuth enabled gadgets for
 * social sites.
 * 
 * Signed fetch sticks identity information in the query string, signed either
 * with the container's private key, or else with a secret shared between the
 * container and the gadget.
 * 
 * Full OAuth redirects the user to the OAuth service provider site to obtain
 * the user's permission to access their data. Read the example in the appendix
 * to the OAuth spec for a summary of how this works (The spec is at
 * http://oauth.net/core/1.0/).
 * 
 * The combination protocol works by sending identity information in all
 * requests, and allows the OAuth dance to happen as well when owner == viewer
 * (by default) or for any viewer when the
 * OAuthFetcherConfig#isViewerAccessTokensEnabled parameter is true. This lets
 * OAuth service providers build up an identity mapping from ids on social
 * network sites to their own local ids.
 */
public interface OAuth2Request {
	public HttpResponse fetch(HttpRequest request);

	/**
	 * Start with an HttpRequest. Throw if there are any attacks in the query.
	 * Throw if there are any attacks in the post body. Build up OAuth parameter
	 * list. Sign it. Add OAuth parameters to new request. Send it.
	 */
	public HttpRequest sanitizeAndSign(HttpRequest base,
			List<Parameter> params, boolean tokenEndpoint)
			throws OAuthRequestException;
}