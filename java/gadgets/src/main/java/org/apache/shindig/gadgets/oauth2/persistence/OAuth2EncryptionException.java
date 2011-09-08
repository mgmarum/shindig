/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2.persistence;

//NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2EncryptionException extends OAuth2PersistenceException {
  /**
   * 
   */
  private static final long serialVersionUID = 1L;

  public OAuth2EncryptionException(final Exception cause) {
    super(cause);
  }
}
