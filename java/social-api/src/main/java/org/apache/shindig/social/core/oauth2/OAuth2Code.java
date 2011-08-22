package org.apache.shindig.social.core.oauth2;

import java.util.List;

import org.apache.shindig.social.core.oauth2.OAuth2Types.CodeType;

/**
 * Represents a "code" string in an OAuth 2.0 handshake, including
 * authorization code, access token, or refresh token.  These signatures may
 * all expire.  They may also be associated with a redirect_url and/or another
 * code.
 */
public class OAuth2Code implements Comparable<OAuth2Code> {
  
  private String value;
  private String redirectUri;
  private long expiration;
  private List<String> scope;
  private OAuth2Client client;
  private OAuth2Code associatedCode;
  private CodeType type;
  
  public OAuth2Code() {
    
  }
    
  public OAuth2Code(String value, String redirectUri, long expiration, List<String> scope) {
    this.value = value;
    this.redirectUri = redirectUri;
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
  
  public String getRedirectUri() {
    return redirectUri;
  }
  
  public void setRedirectUri(String redirectUri) {
    this.redirectUri = redirectUri;
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
  
  public void setType(CodeType type) {
    this.type = type;
  }
  
  public CodeType getType() {
    return type;
  }
  
  public void setAssociatedCode(OAuth2Code code) {
    this.associatedCode = code;
  }
  
  public OAuth2Code getAssociatedCode() {
    return associatedCode;
  }
}
