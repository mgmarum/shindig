package org.apache.shindig.social.core.oauth2;

import java.util.List;

/**
 * Represents a "signature" string in an OAuth 2.0 handshake, including
 * authorization code, access token, or refresh token.  These signatures may
 * all expire.  They may also be associated with a redirect_url and/or another
 * signature.
 */
public class OAuth2Code implements Comparable<OAuth2Code> {
  
  private String value;
  private String redirectURI;
  private long expiration;
  private List<String> scope;
  private OAuth2Client client = null;
  
  public OAuth2Code() {
    
  }
    
  public OAuth2Code(String value, String redirectUri, long expiration, List<String> scope) {
    this.value = value;
    this.redirectURI = redirectUri;
    this.expiration = expiration;
    this.scope = scope;
  }
  
  public OAuth2Code(String value) {
    this.value = value;
  }

  public String getValue() { 
    return value;
  }
  
  public void setValue(String value) {
    this.value = value;
  }
  
  public String getRedirectURI() {
    return redirectURI;
  }
  
  public void setRedirectUri(String redirectUri) {
    this.redirectURI = redirectUri;
  }
  
  public long getExpiration() {
    return expiration;
  }
  
  public void setExpiration(long expiration) {
    this.expiration = expiration;
  }

  public int compareTo(OAuth2Code target) {
    return value.compareTo(target.getValue());
  }
  
  public List<String> getScope() {
    return scope;
  }
  
  public void setScope(List<String> scope) {
    this.scope = scope;
  }

  public void setClient(OAuth2Client client) {
    this.client = client;
  }

  public OAuth2Client getClient() {
    return client;
  }
}
