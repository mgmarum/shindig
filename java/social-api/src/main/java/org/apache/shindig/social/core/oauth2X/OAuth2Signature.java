package org.apache.shindig.social.core.oauth2X;

import java.util.List;

/**
 * Represents a "signature" string in an OAuth 2.0 handshake, including
 * authorization code, access token, or refresh token.  These signatures may
 * all expire.  They may also be associated with a redirect_url and/or another
 * signature.
 */
public class OAuth2Signature implements Comparable<OAuth2Signature> {
  
  private String signature;
  private String redirectUri;
  private String associatedSignature;
  private long expiration;
  private List<String> scope;
  
  public OAuth2Signature() {
    
  }
    
  public OAuth2Signature(String signature, String redirectUri,
      String associatedSignature, long expiration, List<String> scope) {
    this.signature = signature;
    this.redirectUri = redirectUri;
    this.associatedSignature = associatedSignature;
    this.expiration = expiration;
    this.scope = scope;
  }
  
  public String getSignature() { 
    return signature;
  }
  
  public void setSignature(String signature) {
    this.signature = signature;
  }
  
  public String getRedirectUri() {
    return redirectUri;
  }
  
  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
  }
  
  public String getAssociatedSignature() {
    return associatedSignature;
  }
  
  public void setAssociatedSignature(String associatedSignature) {
    this.associatedSignature = associatedSignature;
  }
  
  public long getExpiration() {
    return expiration;
  }
  
  public void setExpiration(long expiration) {
    this.expiration = expiration;
  }

  public int compareTo(OAuth2Signature target) {
    return signature.compareTo(target.getSignature());
  }
  
  public List<String> getScope() {
    return scope;
  }
  
  public void setScope(List<String> scope) {
    this.scope = scope;
  }
}
