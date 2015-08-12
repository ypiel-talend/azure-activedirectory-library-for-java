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

import java.text.ParseException;
import java.util.HashMap;

import org.easymock.EasyMock;
import org.powermock.api.easymock.PowerMock;
import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

/**
 *
 */
@Test(groups = { "checkin" })
public class UserInfoTest extends AbstractAdalTests {

    @Test
    public void testCreateFromProfileInfoClaims_AllValues() throws Exception
    {
        final AdalAccessTokenResponse response = AdalAccessTokenResponse
                .parseJsonObject(JSONObjectUtils
                        .parseJSONObject(TestConfiguration.HTTP_RESPONSE_FROM_AUTH_CODE));
        UserInfo info = UserInfo.createFromProfileInfoClaims(response.getProfileInfo());
        Assert.assertNotNull(info);
    }

    @Test
    public void testCreateFromIdTokenClaims_Null() throws com.nimbusds.oauth2.sdk.ParseException {
        Assert.assertNull(UserInfo.createFromProfileInfoClaims(null));
    }

}
