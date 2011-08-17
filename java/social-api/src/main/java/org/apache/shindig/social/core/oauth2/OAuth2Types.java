package org.apache.shindig.social.core.oauth2;

/**
 * A collection of OAuth 2.0's enumerated types.
 */
public class OAuth2Types {
  
  /**
   * Enumerated error types in the OAuth 2.0 specification.
   */
  public static enum ErrorType {
    INVALID_REQUEST("invalid_request"),
    INVALID_CLIENT("invalid_client"),
    INVALID_GRANT("invalid_grant"),
    UNAUTHORIZED_CLIENT("unauthorized_client"),
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type"),
    INVALID_SCOPE("invalid_scope"),
    ACCESS_DENIED("access_denied"),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),
    SERVER_ERROR("server_error"),
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable");
    
    private final String name;
    
    private ErrorType(String name) {
      this.name = name;
    }

    public String toString() {
      return name;
    }
  }
  
  /**
   * Enumerated response types in the OAuth 2.0 specification.
   */
  public static enum ResponseType {
    CODE("code"),
    TOKEN("token");
    
    private final String name;
    
    private ResponseType(String name) {
      this.name = name;
    }

    public String toString() {
      return name;
    }
  }
  

  
  /**
   * Enumerated token types in the OAuth 2.0 specification.
   */
  public static enum TokenFormat {
    BEARER("bearer"),
    MAC("mac");
    
    private final String name;
    
    private TokenFormat(String name) {
      this.name = name;
    }

    public String toString() {
      return name;
    }
  }
}
