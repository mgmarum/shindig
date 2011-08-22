package org.apache.shindig.social.core.oauth2;



/**
 * Represents an OAuth 2.0 client.
 */
public class OAuth2Client {
  
  protected String id;
  protected String secret;
  protected String redirectURL;
  protected String title;
  protected String iconUrl;
  protected ClientType type;
  
  /**
   * Gets the client's ID.
   * 
   * @return String represents the client's ID.
   */
  public String getId() {
    return id;
  }
  
  /**
   * Sets the client's ID.
   * 
   * @param id represents the client's ID.
   */
  public void setId(String id) {
    this.id = id;
  }
  
  /**
   * Gets the client's secret.
   * 
   * @return String represents the client's secret
   */
  public String getSecret() {
    return secret;
  }
  
  /**
   * Sets the client's secret.
   * 
   * @param secret represents the client's secret
   */
  public void setSecret(String secret) {
    this.secret = secret;
  }
  
  /**
   * Gets the client's redirect URI.
   * 
   * @return String represents the client's redirect URI
   */
  public String getRedirectURI() {
    return redirectURL;
  }
  
  /**
   * Sets the client's redirect URI.
   * 
   * @param redirectUri represents the client's redirect URI
   */
  public void setRedirectURI(String redirectUri) {
    this.redirectURL = redirectUri;
  }
  
  /**
   * Gets the client's title.
   * 
   * @return String represents the client's title
   */
  public String getTitle() {
    return title;
  }
  
  /**
   * Sets the client's title.
   * 
   * @param title represents the client's title
   */
  public void setTitle(String title) {
    this.title = title;
  }
  
  /**
   * Gets the client's icon URL.
   * 
   * @return String represents the client's icon URL
   */
  public String getIconUrl() {
    return iconUrl;
  }
  
  /**
   * Sets the client's icon URL.
   * 
   * @param iconUrl represents the client's icon URL
   */
  public void setIconUrl(String iconUrl) {
    this.iconUrl = iconUrl;
  }
  
  /**
   * Gets the client's type.
   * 
   * @return ClientType represents the client's type
   */
  public ClientType getType() {
    return type;
  }
  
  /**
   * Sets the client's type.
   * 
   * @param clientType represents the client's type
   */
  public void setType(ClientType type) {
    this.type = type;
  }
  
  /**
   * Enumerated client types in the OAuth 2.0 specification.
   */
  public static enum ClientType {
    PUBLIC("public"),
    CONFIDENTIAL("confidential");
    
    private final String name;
    
    private ClientType(String name) {
      this.name = name;
    }

    public String toString() {
      return name;
    }
  }
}
