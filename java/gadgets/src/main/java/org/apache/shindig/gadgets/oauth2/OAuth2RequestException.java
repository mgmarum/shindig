/**
 * This class is intended to be contributed back to the
 * Open Source Shindig project.  (Or at least submitted
 * for review.)  
 * 
 * NO IBM CONFIDENTIAL CODE OR INFORMATION!
 */
package org.apache.shindig.gadgets.oauth2;

import com.google.common.base.Preconditions;

/**
 * Thrown by OAuth request routines.
 * 
 * @since 2.0.0
 */

// NO IBM CONFIDENTIAL CODE OR INFORMATION!

public class OAuth2RequestException extends Exception {

  /**
   * Error code for the client.
   */
  private String error;

  /**
   * Error text for the client.
   */
  private String errorText;

  /**
   * Create an exception and record information about the exception to be
   * returned to the gadget.
   * 
   * @param error
   */
  public OAuth2RequestException(final OAuth2Error error) {
    this(error.name(), error.toString());
  }

  /**
   * Create an exception and record information about the exception to be
   * returned to the gadget.
   * 
   * @param error
   * @param errorText
   */
  public OAuth2RequestException(final OAuth2Error error, final String errorText) {
    this(error.name(), String.format(error.toString(), errorText));
  }

  /**
   * Create an exception and record information about the exception to be
   * returned to the gadget.
   * 
   * @param error
   * @param errorText
   * @param cause
   */
  public OAuth2RequestException(final OAuth2Error error, final String errorText,
      final Throwable cause) {
    this(error.name(), String.format(error.toString(), errorText), cause);
  }

  /**
   * Create an exception and record information about the exception to be
   * returned to the gadget.
   * 
   * @param error
   * @param errorText
   */
  public OAuth2RequestException(final String error, final String errorText) {
    super('[' + error + ',' + errorText + ']');
    this.error = Preconditions.checkNotNull(error);
    this.errorText = Preconditions.checkNotNull(errorText);
  }

  /**
   * Create an exception and record information about the exception to be
   * returned to the gadget.
   * 
   * @param error
   * @param errorText
   * @param cause
   */
  public OAuth2RequestException(final String error, final String errorText, final Throwable cause) {
    super('[' + error + ',' + errorText + ']', cause);
    this.error = Preconditions.checkNotNull(error);
    this.errorText = Preconditions.checkNotNull(errorText);
  }

  /**
   * Create an exception and record information about the exception to be
   * returned to the gadget.
   * 
   * @param message
   */
  public OAuth2RequestException(final String message) {
    super(message);
  }

  /**
   * Create an exception and record information about the exception to be
   * returned to the gadget.
   * 
   * @param message
   * @param cause
   */
  public OAuth2RequestException(final String message, final Throwable cause) {
    super(message, cause);
  }

  /**
   * Get the error code
   * 
   * @return
   */
  public String getError() {
    return this.error;
  }

  /**
   * Get a meaningful description of the exception
   * 
   * @return
   */
  public String getErrorText() {
    return this.errorText;
  }

  @Override
  public String getMessage() {
    return this.errorText;
  }

  @Override
  public String toString() {
    return '[' + this.error + ',' + this.errorText + ']';
  }
}
