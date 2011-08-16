package org.apache.shindig.social.core.oauth2X;

/**
 * A collection of OAuth 2.0's enumerated types.
 */
public class OAuth2Types {

  /**
   * Enumerated grant types in the OAuth 2.0 specification.
   */
  public static enum GrantType {
    REFRESH_TOKEN("refresh_token"),
    AUTHORIZATION_CODE("authorization_code"),
    PASSWORD("password"),
    CLIENT_CREDENTIALS("client_credentials");
    
    private final String name;
    
    private GrantType(String name) {
      this.name = name;
    }

    public String toString() {
      return name;
    }
  }
  
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
  
  /**
   * Enumerated token types in the OAuth 2.0 specification.
   */
  public static enum TokenType {
    BEARER("bearer"),
    MAC("mac");
    
    private final String name;
    
    private TokenType(String name) {
      this.name = name;
    }

    public String toString() {
      return name;
    }
  }
}
