/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import net.oauth.OAuthException;
import net.oauth.OAuthMessage;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.shindig.gadgets.oauth2.OAuth2Exception;
import org.apache.shindig.gadgets.oauth2.OAuth2.ClientAuthMethod;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!
public class OAuth2Accessor implements Cloneable, Serializable {

	private static final long serialVersionUID = 985492452938876125L;

	public OAuth2Accessor(OAuth2Consumer consumer) {
		this.consumer = consumer;
	}

	public final OAuth2Consumer consumer;
	public String refreshToken;
	public String accessToken;
	public String tokenSecret;
	//authorization code received from authorization server
	public String authorizationCode;
	
	//properties for any possible extension
	private final Map<String, Object> properties = new HashMap<String, Object>();

    public OAuth2Accessor clone() {
        try {
            return (OAuth2Accessor) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }
    
    /**
     * Construct a request message containing the given parameters but no body.
     * Don't send the message, merely construct it. The caller will ordinarily
     * send it, for example by calling OAuthClient.invoke or access.
     * 
     * @param method
     *            the HTTP request method. If this is null, use the default
     *            method; that is getProperty("httpMethod") or (if that's null)
     *            consumer.getProperty("httpMethod") or (if that's null)
     *            OAuthMessage.GET.
     */
    public OAuthMessage newRequestMessage(String method, String url, Collection<? extends Map.Entry> parameters,
            InputStream body) throws OAuthException, IOException, URISyntaxException {
        if (method == null) {
            method = (String) this.getProperty("httpMethod");
            if (method == null) {
                method = (String) this.consumer.getProperty("httpMethod");
                if (method == null) {
                    method = OAuthMessage.GET;
                }
            }
        }
        OAuthMessage message = new OAuthMessage(method, url, parameters, body);
        //message.addRequiredParameters(this);
        return message;
    }

    public OAuthMessage newRequestMessage(String method, String url, Collection<? extends Map.Entry> parameters)
            throws OAuthException, IOException, URISyntaxException {
        return newRequestMessage(method, url, parameters, null);
    }

    public Object getProperty(String name) {
        return properties.get(name);
    }

    public void setProperty(String name, Object value) {
        properties.put(name, value);
    }

	public OAuth2Message getAccessTokenMessage(ClientAuthMethod method)
			throws OAuth2Exception {
		return null;
	}

	public void validate(OAuth2Message message) throws OAuth2Exception {

	}

	public HttpResponse access(HttpUriRequest request) throws OAuth2Exception {
		return null;
	}

}
