/*******************************************************************************
 * Copyright © Microsoft Open Technologies, Inc.
 * 
 * All Rights Reserved
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 * 
 * See the Apache License, Version 2.0 for the specific language
 * governing permissions and limitations under the License.
 ******************************************************************************/
package com.microsoft.aad.adal4j;

class AuthenticationConstants {

    final static int AAD_JWT_TOKEN_LIFETIME_SECONDS = 60 * 10;
    final static String RESOURCE = "resource";

    static final String PROFILE_TOKEN_SUBJECT = "sub";
    static final String PROFILE_TOKEN_TENANTID = "tid";
    static final String PROFILE_TOKEN_VERSION = "version";
    static final String PROFILE_TOKEN_PREF_USERNAME = "preferred_username";
    static final String PROFILE_TOKEN_NAME = "name";
}
