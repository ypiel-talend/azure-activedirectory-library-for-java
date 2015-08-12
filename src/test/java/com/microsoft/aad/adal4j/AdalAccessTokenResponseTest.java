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

import net.minidev.json.JSONObject;

import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

@Test(groups = { "checkin" })
public class AdalAccessTokenResponseTest extends AbstractAdalTests {

    public static final String profileInfoString = "ewogICJ2ZXJzaW9uIjogIjE"
            + "uMCIsCiAgInByZWZlcnJlZF91c2VybmFtZSI6ICJ1c2VyQG5hbWUuY29tIiwK"
            + "ICAic3ViIjogImhmZ2lydWhnM2lzMzQ0ZXVmciIsCiAgInRpZCI6ICI4MDI5M"
            + "zgwaGpobWhrajMyNDA5ODQyNCIsCiAgIm5hbWUiOiAic2FtcGxlIG5hbWUiCn0";

    private final String idToken = "idToken";
    private final long idTokenExpiresIn = 3599;

    @Test
    public void testConstructor() throws ParseException {
        final AdalAccessTokenResponse response = new AdalAccessTokenResponse(
                new BearerAccessToken("access_token"), new RefreshToken(
                        "refresh_token"), idToken, idTokenExpiresIn,
                new String[] { "openid", "Scope1" }, profileInfoString);
        Assert.assertNotNull(response);
        final JWT jwt = response.getIDToken();
        Assert.assertTrue(jwt.getJWTClaimsSet().getAllClaims().size() >= 0);
    }

    @Test
    public void testParseJsonObject() throws Exception {

        final AdalAccessTokenResponse response = AdalAccessTokenResponse
                .parseJsonObject(JSONObjectUtils
                        .parseJSONObject(TestConfiguration.HTTP_RESPONSE_FROM_AUTH_CODE));
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getIDToken());
        Assert.assertFalse(StringHelper.isBlank(response.getIDTokenString()));
        Assert.assertFalse(StringHelper.isBlank(response.getScope()));
        JSONObject set = response.getProfileInfo();
        Assert.assertNotNull(set);
    }

}
