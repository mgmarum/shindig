/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.sample;

/**
 * Data structure representing an OAuth2 consumer key and secret
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2StoreConsumerKeyAndSecret {

  public static enum OAuth2KeyType {
  }

  /** Value for oauth_consumer_key */
  private final String consumerKey;

  /** HMAC secret, or RSA private key, depending on keyType */
  private final String consumerSecret;

  /** Type of key */
  private final OAuth2KeyType keyType;

  /** Name of public key to use with xoauth_public_key parameter. May be null */
  private final String keyName;

  /** Callback URL associated with this consumer key */
  private final String callbackUrl;

  public OAuth2StoreConsumerKeyAndSecret(final String key, final String secret,
      final OAuth2KeyType type, final String name, final String callbackUrl) {
    this.consumerKey = key;
    this.consumerSecret = secret;
    this.keyType = type;
    this.keyName = name;
    this.callbackUrl = callbackUrl;
  }

  public String getConsumerKey() {
    return this.consumerKey;
  }

  public String getConsumerSecret() {
    return this.consumerSecret;
  }

  public OAuth2KeyType getKeyType() {
    return this.keyType;
  }

  public String getKeyName() {
    return this.keyName;
  }

  public String getCallbackUrl() {
    return this.callbackUrl;
  }
}
