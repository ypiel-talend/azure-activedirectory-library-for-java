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

import org.testng.Assert;
import org.testng.annotations.Test;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;

@Test(groups = { "checkin" })
public class AdalAccessTokenResponseTest extends AbstractAdalTests {

    private final String profileInfoString = "eyJhdWQiOiI5MDgzY2NiOC04YTQ2LT"
            + "QzZTctODQzOS0xZDY5NmRmOTg0YWUiLCJpc3MiOiJodHRwczovL3N0cy53aW"
            + "5kb3dzLm5ldC8zMGJhYTY2Ni04ZGY4LTQ4ZTctOTdlNi03N2NmZDA5OTU5NjM"
            + "vIiwiaWF0IjoxNDAwNTQxMzk1LCJuYmYiOjE0MDA1NDEzOTUsImV4cCI6MTQw"
            + "MDU0NTU5NSwidmVyIjoiMS4wIiwidGlkIjoiMzBiYWE2NjYtOGRmOC00OGU3L"
            + "Tk3ZTYtNzdjZmQwOTk1OTYzIiwib2lkIjoiNGY4NTk5ODktYTJmZi00MTFlLT"
            + "kwNDgtYzMyMjI0N2FjNjJjIiwidXBuIjoiYWRtaW5AYWFsdGVzdHMub25taWN"
            + "yb3NvZnQuY29tIiwidW5pcXVlX25hbWUiOiJhZG1pbkBhYWx0ZXN0cy5vbm1p"
            + "Y3Jvc29mdC5jb20iLCJzdWIiOiJCczVxVG4xQ3YtNC10VXIxTGxBb3pOS1NRd0"
            + "Fjbm4ydHcyQjlmelduNlpJIiwiZmFtaWx5X25hbWUiOiJBZG1pbiIsImdpdmVu"
            + "X25hbWUiOiJBREFMVGVzdHMifQ";

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
    public void testParseJsonObject()
            throws com.nimbusds.oauth2.sdk.ParseException {
        final AdalAccessTokenResponse response = AdalAccessTokenResponse
                .parseJsonObject(JSONObjectUtils
                        .parseJSONObject(TestConfiguration.HTTP_RESPONSE_FROM_AUTH_CODE));
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getIDToken());
        Assert.assertFalse(StringHelper.isBlank(response.getIDTokenString()));
        Assert.assertFalse(StringHelper.isBlank(response.getScope()));
    }
}
