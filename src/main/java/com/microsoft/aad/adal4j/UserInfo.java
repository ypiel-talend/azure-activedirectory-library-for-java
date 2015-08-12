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

import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

/**
 * Contains information of a single user.
 */
public class UserInfo implements Serializable {

    private static final long serialVersionUID = 1L;
    String uniqueId;
    String displayableId;
    String name;
    String version;
    String tenantId;

    private UserInfo() {
    }

    public String getDisplayableId() {
        return displayableId;
    }

    /**
     * Get user id
     * 
     * @return String value
     */
    public String getUniqueId() {
        return uniqueId;
    }

    /**
     * Get Tenant Id
     * 
     * @return String value
     */
    public String getTenantId() {
        return tenantId;
    }

    /**
     * Get given name
     * 
     * @return String value
     */
    public String getName() {
        return name;
    }

    /**
     * Get family name
     * 
     * @return String value
     */
    public String getVersion() {
        return version;
    }

    static UserInfo createFromProfileInfoClaims(final JSONObject obj)
            throws com.nimbusds.oauth2.sdk.ParseException {

        if (obj == null || obj.size() == 0) {
            return null;
        }

        String uniqueId = null;
        String displayableId = null;

        if (!StringHelper.isBlank(JSONObjectUtils.getString(obj,
                AuthenticationConstants.PROFILE_TOKEN_SUBJECT))) {
            uniqueId = JSONObjectUtils.getString(obj,
                    AuthenticationConstants.PROFILE_TOKEN_SUBJECT);
        }

        if (!StringHelper.isBlank(JSONObjectUtils.getString(obj,
                AuthenticationConstants.PROFILE_TOKEN_PREF_USERNAME))) {
            displayableId = JSONObjectUtils.getString(obj,
                    AuthenticationConstants.PROFILE_TOKEN_PREF_USERNAME);
        }

        final UserInfo userInfo = new UserInfo();
        userInfo.uniqueId = uniqueId;
        userInfo.displayableId = displayableId;
        userInfo.name = JSONObjectUtils.getString(obj,
                AuthenticationConstants.PROFILE_TOKEN_NAME);
        userInfo.tenantId = JSONObjectUtils.getString(obj,
                AuthenticationConstants.PROFILE_TOKEN_TENANTID);
        userInfo.version = JSONObjectUtils.getString(obj,
                AuthenticationConstants.PROFILE_TOKEN_VERSION);

        return userInfo;
    }

}
