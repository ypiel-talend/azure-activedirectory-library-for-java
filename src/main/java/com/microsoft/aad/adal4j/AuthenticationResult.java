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

import java.io.Serializable;
import java.util.Date;

/**
 * Contains the results of one token acquisition operation.
 */
public final class AuthenticationResult implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String tokenType;
    private final Date idTokenExpiresOn;
    private final Date expiresOn;
    private final UserInfo userInfo;
    private final String accessToken;
    private final String idToken;
    private final String refreshToken;
    private final boolean isMultipleResourceRefreshToken;

    public AuthenticationResult(final String tokenType,
            final String accessToken, final String refreshToken,
            final long expiresIn, final String idToken,
            final long idTokenExpiresIn, final UserInfo userInfo,
            final boolean isMultipleResourceRefreshToken) {
        this.tokenType = tokenType;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.idToken = idToken;
        
        Date now = new Date();
        now.setTime(now.getTime() + (expiresIn * 1000));
        this.expiresOn = now;

        now = new Date();
        now.setTime(now.getTime() + (idTokenExpiresIn * 1000));
        this.idTokenExpiresOn = now;
        
        this.userInfo = userInfo;
        this.isMultipleResourceRefreshToken = isMultipleResourceRefreshToken;
    }

    public String getTokenType() {
        return tokenType;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getIdToken() {
        return idToken;
    }
    
    public String getRefreshToken() {
        return refreshToken;
    }

    public Date getIdTokenExpiresOn() {
        return idTokenExpiresOn;
    }
    
    public Date getExpiresOn() {
        return expiresOn;
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

    public boolean isMultipleResourceRefreshToken() {
        return isMultipleResourceRefreshToken;
    }
}
