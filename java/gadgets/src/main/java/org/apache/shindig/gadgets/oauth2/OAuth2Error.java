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

/**
 * Error strings to be returned to gadgets as "oauthError" data.
 * 
 * This class, and error handling in general, still needs a lot of work.
 * 
 */
public enum OAuth2Error {
  UNKNOWN_PROBLEM("%s"),

  BAD_OAUTH_CONFIGURATION("%s"),

  MISSING_SERVER_RESPONSE("No response from server"),

  BAD_OAUTH_TOKEN_URL("No %s URL specified"),

  MISSING_OAUTH_PARAMETER("No %s returned from service provider"),

  UNAUTHENTICATED("Unauthenticated OAuth fetch"),

  NOT_OWNER("Page viewer is not page owner"),
  
  INVALID_REQUEST("%s"),

  UNAUTHORIZED_CLIENT("%s"),

  ACCESS_DENIED("Access denied by user"),

  UNSUPPORTED_RESPONSE_TYPE("%s"),

  INVALID_SCOPE("%s"),

  SERVER_ERROR("%s"),

  NO_STATE("Authorization Server did not return a state"),

  INVALID_STATE("A valid state for the OAuth2 Authorization response could not be found"),

  INVALID_STATE_CHANGE("Invalid OAuth2 State change requested by OAuth2CallbackServlet"),

  INVALID_CLIENT("Invalid OAuth2 State change requested by OAuth2CallbackServlet"),

  INVALID_GRANT("The provided authorization grant is invalid"),

  UNSUPPORTED_GRANT_TYPE("The authorization grant type is not supported"),

  TEMPORARILY_UNAVAILABLE("%s");

  private final String formatString;

  OAuth2Error(final String formatString) {
    this.formatString = formatString;
  }

  @Override
  public String toString() {
    return this.formatString;
  }
}
