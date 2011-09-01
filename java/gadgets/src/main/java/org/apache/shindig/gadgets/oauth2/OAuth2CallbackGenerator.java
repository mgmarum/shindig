/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import org.apache.shindig.gadgets.http.HttpRequest;

import com.google.inject.ImplementedBy;

/**
 * Figures out the OAuth callback URL to send service providers.
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

@ImplementedBy(GadgetOAuth2CallbackGenerator.class)
public interface OAuth2CallbackGenerator {
  String generateCallback(OAuth2FetcherConfig fetcherConfig, String baseCallback,
      HttpRequest request, OAuth2ResponseParams responseParams) throws OAuth2RequestException;
}
