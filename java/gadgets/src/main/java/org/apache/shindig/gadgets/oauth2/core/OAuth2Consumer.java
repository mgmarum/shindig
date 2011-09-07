/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.core;

import java.util.HashMap;
import java.util.Map;

import net.oauth.OAuthServiceProvider;

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2Consumer {

	public OAuth2Consumer(String callbackURL, String consumerKey,
			String consumerSecret, OAuth2ServiceProvider serviceProvider) {
		this.callbackURL = callbackURL;
		this.consumerKey = consumerKey;
		this.consumerSecret = consumerSecret;
		this.serviceProvider = serviceProvider;
	}

	private static final long serialVersionUID = 8733203285726230619L;

	public final String callbackURL;
	public final String consumerKey;
	public final String consumerSecret;
	public final OAuth2ServiceProvider serviceProvider;

	private final Map<String, Object> properties = new HashMap<String, Object>();

	public Object getProperty(String name) {
		return properties.get(name);
	}

	public void setProperty(String name, Object value) {
		properties.put(name, value);
	}

}
