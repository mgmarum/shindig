/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*global opensocial */

/**
 * @fileoverview Representation of an email.
 */


/**
 * @class
 * Base interface for all email objects.
 *
 * @name opensocial.Email
 */


/**
 * Base interface for all email objects.
 *
 * @private
 * @constructor
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.21.
 */
opensocial.Email = function(opt_params) {
  this.fields_ = opt_params || {};
};


/**
 * @static
 * @class
 * All of the fields that an email has. These are the supported keys for the
 * <a href="opensocial.Email.html#getField">Email.getField()</a> method.
 *
 * @name opensocial.Email.Field
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.22.
 */
opensocial.Email.Field = {
  /**
   * The email type or label, specified as a String.
   * Examples: work, my favorite store, my house, etc.
   *
   * @member opensocial.Email.Field
   */
  TYPE: 'type',

  /**
   * The email address, specified as a String.
   *
   * @member opensocial.Email.Field
   */
  ADDRESS: 'address'
};


/**
 * Gets data for this body type that is associated with the specified key.
 *
 * @param {string} key The key to get data for;
 *    keys are defined in <a href="opensocial.Email.Field.html"><code>
 *    Email.Field</code></a>.
 * @param {Object.<opensocial.DataRequest.DataRequestFields, Object>}
 *  opt_params Additional
 *    <a href="opensocial.DataRequest.DataRequestFields.html">params</a>
 *    to pass to the request.
 * @return {string} The data.
 * @deprecated since 1.0 see http://opensocial-resources.googlecode.com/svn/spec/1.0/Social-Gadget.xml#rfc.section.A.21.1.1.
 */
opensocial.Email.prototype.getField = function(key, opt_params) {
  return opensocial.Container.getField(this.fields_, key, opt_params);
};
