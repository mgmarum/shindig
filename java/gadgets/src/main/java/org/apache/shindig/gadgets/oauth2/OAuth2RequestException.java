/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shindig.gadgets.oauth2;

import com.google.common.base.Preconditions;

// Could probably gain something by making this more granular.
/**
 * Thrown by OAuth2 request routines.
 * 
 */
public class OAuth2RequestException extends Exception {
  private static final long serialVersionUID = 7670892831898874835L;

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
