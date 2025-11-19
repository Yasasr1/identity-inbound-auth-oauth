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

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.testutil.powermock.PowerMockIdentityBaseTest;

import java.util.Date;

import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

@WithCarbonHome
@PrepareForTest({OAuthServerConfiguration.class, JWTUtils.class, LoggerUtils.class})
public class JWTUtilsTest extends PowerMockIdentityBaseTest {

    @Mock
    private OAuthServerConfiguration oauthServerConfigurationMock;

    @BeforeMethod
    public void setUp() throws Exception {

        long timestampSkew = 300;
        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(oauthServerConfigurationMock);
        when(oauthServerConfigurationMock.getTimeStampSkewInSeconds()).thenReturn(timestampSkew);
        mockStatic(LoggerUtils.class);
        when(LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @DataProvider(name = "getAccessToken")
    public Object[][] getAccessToken() {

        String jwtString =
            "eyJ4NXQiOiJObUptT0dVeE16WmxZak0yWkRSaE5UWmxZVEExWXpkaFpUUmlPV0UwTldJMk0ySm1PVGMxWkEiLCJhbGciOiJSUzI1NiJ9" +
                    ".eyJhdF9oYXNoIjoiR2ptOGFsN21FSkRVYjZuN3V1Mi1qUSIsInN1YiI6ImFkbWluQGNhcmJvbi5zdXBlciIsImF1ZCI6WyJ" +
                    "hVmdieWhBMVY3TWV0ZW1PNEtrUjlFYnBzOW9hIiwiaHR0cHM6XC9cL2xvY2FsaG9zdDo5NDQzXC9vYXV0aDJcL3Rva2VuIl0" +
                    "sImF6cCI6ImFWZ2J5aEExVjdNZXRlbU80S2tSOUVicHM5b2EiLCJhdXRoX3RpbWUiOjE1MjUyMzYzMzcsImlzcyI6Imh0dHB" +
                    "zOlwvXC8xMC4xMDAuOC4yOjk0NDNcL29hdXRoMlwvdG9rZW4iLCJleHAiOjE1MjUyMzk5MzcsImlhdCI6MTUyNTIzNjMzN30" +
                    ".DOPv7UHymV3zJJpxxWqbGcrvjY-OOzmdJVUxwHorDlOGABP_X_Krd584rLIbcYFmd8q5wSUuX21wXCLCOXFli1CUC-ZfP0S" +
                    "0fJqUZv_ynNo6NTFY9d3-sv0b7QYT-8mnxSmjqqsmDrOcxlD7gcYkkr1pLLQe9ZK2B_lR5KZlMW0";

        return new Object[][]{
                // accessToken, isJWT
                {jwtString, true},
                {"00090-asds-sdasdewe-1212", false},
                {null, false},
                {"", false}
        };
    }

    @Test(dataProvider = "getAccessToken")
    public void testIsJWT(String accessToken, boolean isJWT) {

        assertEquals(JWTUtils.isJWT(accessToken), isJWT, "isJWT method failed for accessToken: " + accessToken);
    }

    @DataProvider(name = "getExpiryTime")
    public Object[][] getExpiryTime() {

        return new Object[][]{
                // expiryTime in millis, True if the token is not expired, false otherwise.
                {System.currentTimeMillis() - 100000, false},
                {System.currentTimeMillis() + 300000000, true},
        };
    }

    @Test(dataProvider = "getExpiryTime")
    public void testCheckExpiryTime(long time, boolean isExpired) {

        assertEquals(JWTUtils.checkExpirationTime(new Date(time)), isExpired,
                "checkExpiryTime method failed for time: " + time);
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testCheckNotBeforeTimeNegative() throws IdentityOAuth2Exception {

        JWTUtils.checkNotBeforeTime(new Date(System.currentTimeMillis() + 30000000));
    }

    @Test
    public void testCheckNotBeforeTime() {

        try {
            JWTUtils.checkNotBeforeTime(new Date(System.currentTimeMillis() + 30000));
        } catch (IdentityOAuth2Exception e) {
            fail("checkNotBeforeTime method failed for future time", e);
        }
    }
}
