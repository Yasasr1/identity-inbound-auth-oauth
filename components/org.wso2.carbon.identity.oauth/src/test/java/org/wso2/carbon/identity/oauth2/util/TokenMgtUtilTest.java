/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import com.nimbusds.jwt.JWTClaimsSet;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

@WithCarbonHome
@PrepareForTest({OAuthServerConfiguration.class, JWTUtils.class, TokenMgtUtil.class})
public class TokenMgtUtilTest extends PowerMockIdentityBaseTest {

    @Mock
    private OAuthServerConfiguration oauthServerConfigurationMock;

    private final String nonPersistenceAccessToken =
            "eyJ4NXQiOiJOVGRtWmpNNFpEazNOalkwWXpjNU1tWm1PRGd3TVRFM01XWXdOREU1TVdSbFpEZzROemM0WkEiLCJraWQiOiJNell4TW1" +
                    "Ga09HWXdNV0kwWldObU5EY3hOR1l3WW1NNFpUQTNNV0kyTkRBelpHUXpOR00wWkdSbE5qSmtPREZrWkRSaU9URmtNV0ZoTX" +
                    "pVMlpHVmxOZ19SUzI1NiIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJhZG1pbiIsImF1dCI6IkFQUExJQ0FUSU9OX1VTRVIiL" +
                    "CJjb3VudHJ5IjoiTGFua2EiLCJlbnRpdHlUeXBlIjoiVVNFUl9JRCIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0" +
                    "NFwvb2F1dGgyXC90b2tlbiIsImFwcF90ZCI6ImNhcmJvbi5zdXBlciIsImdpdmVuX25hbWUiOiJhZG1pbiIsImVudGl0eV9" +
                    "pZCI6ImQxMGViYmYxLTZlMzAtNDk3Yi04OGNhLWM1OGFiNTU5MjY5NiIsImF1ZCI6InVwSk80R3hWUFFNek5ZZ2k2bGYwb3" +
                    "Z0WHNyd2EiLCJuYmYiOjE3NTUwNjEzODcsInRva2VuX2lkIjoiZmQwYjQxY2ItMGJhNC00ZDJlLWFhMjgtNWY0MGM1YzQ5Z" +
                    "WNiIiwiYXpwIjoidXBKTzRHeFZQUU16TllnaTZsZjBvdnRYc3J3YSIsInNjb3BlIjoiaW50ZXJuYWxfdXNlcl9tZ3RfY3Jl" +
                    "YXRlIGludGVybmFsX3VzZXJfbWd0X2RlbGV0ZSBvcGVuaWQiLCJuYW1lIjoiYWRtaW4iLCJleHAiOjE3NTUwNjQ5ODcsImd" +
                    "yYW50VHlwZSI6InJlZnJlc2hfdG9rZW4iLCJpYXQiOjE3NTUwNjEzODcsImp0aSI6ImVjY2UwZGRkLWJjMDctNDkxMS05NW" +
                    "RkLWZlMGQxYTViZGNkMSIsImlzX2ZlZGVyYXRlZCI6ZmFsc2UsInVzZXJfdGQiOiJjYXJib24uc3VwZXIifQ.ifWJpOTi8V" +
                    "oGxYWO4LnaEpDKTWKT7gGv3PY1lOCYuJ6WXhpIzNs6nF1u6h4rSMSWmxmQZ_Kk6o4csIdlndx33r-SrlCOIFIUx7TE5bV46" +
                    "NcCxesfPsnHchlRmfK2V60w-eIxbQuOZ8UcqK9k7zt9gKoxYUZC9A9gpVgnYOzs4fcOK1UjzKODLlz5Ax7c49IbU3SIA7BH" +
                    "NYDYj3zAOZt_hSpYrYOqc1FvA32TpPoumW1l6R2tIqUcT90ihU0l6k1kDJGE21jW-ptTMMqBJ3s8SCFpr2DSvrsM2MhPQux" +
                    "GQC3_dcWTZUP9-6j2CeDHgkssNLWIgBD6dZ5UPddXlaEGHQ";

    @BeforeMethod
    public void setUp() throws Exception {

        long timestampSkew = 300;
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
        when(oauthServerConfigurationMock.getTimeStampSkewInSeconds()).thenReturn(timestampSkew);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @DataProvider(name = "getRefreshToken")
    public Object[][] getRefreshToken() {

        return new Object[][]{
                // refreshToken, isHybridPersistedToken
                {"npr_bafd3fce-c29e-39fc-a1f3-e9d4aa82663a", true},
                {"bafd3fce-c29e-39fc-a1f3-e9d4aa82663a", false},
                {null, false},
                {"", false}
        };
    }

    @Test(dataProvider = "getRefreshToken")
    public void testIsHybridPersistedToken(String refreshToken, boolean isHybridPersistedToken) {

        assertEquals(TokenMgtUtil.isHybridPersistedToken(refreshToken), isHybridPersistedToken,
                "isHybridPersistedToken method failed for refreshToken: " + refreshToken);
    }

    @Test
    public void testGetTokenIdentifier() throws IdentityOAuth2Exception {

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("sampleUser").jwtID("1111").build();
        assertEquals(TokenMgtUtil.getTokenIdentifier(jwtClaimsSet), "1111",
                " Token identifier should match the JWT ID");
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testGetTokenIdentifierNegative() throws IdentityOAuth2Exception {

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject("sampleUser").build();
        TokenMgtUtil.getTokenIdentifier(jwtClaimsSet);
    }

    @Test
    public void testGetTokenIDFromNonPersistenceAccessToken() throws IdentityOAuth2Exception {

        String tokenId = TokenMgtUtil.getTokenIDFromNonPersistenceAccessToken(nonPersistenceAccessToken);
        assertEquals(tokenId, "fd0b41cb-0ba4-4d2e-aa28-5f40c5c49ecb",
                "Token ID should match the expected value from non-persistence access token");
    }

    @Test
    public void testIsNonPersistenceAccessToken() {

        assertTrue(TokenMgtUtil.isNonPersistenceAccessToken(nonPersistenceAccessToken),
                "isNonPersistenceAccessToken method failed for non-persistence access token");
    }
}
