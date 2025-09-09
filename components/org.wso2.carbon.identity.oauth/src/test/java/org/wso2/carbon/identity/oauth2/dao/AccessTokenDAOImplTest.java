/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.oauth2.dao;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.util.DAOUtils;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

@WithCarbonHome
@PrepareForTest({IdentityDatabaseUtil.class, OAuthServerConfiguration.class, OAuth2Util.class, IdentityUtil.class})
public class AccessTokenDAOImplTest extends PowerMockTestCase {

    public static final String H2_SCRIPT_NAME = "identity.sql";
    public static final String H2_SCRIPT2_NAME = "insert_token_binding.sql";
    public static final String DB_NAME = "AccessTokenDB";
    private static final String EXPIRED_TOKEN_ID = "expired_token_id";
    private static final String TEST_TENANT_DOMAIN = "TestTenantDomain";
    private static final String TEST_USER1 = "user1";
    private static final String PRIMARY_USER_STORE = "PRIMARY";
    Connection connection = null;
    private AccessTokenDAOImpl accessTokenDAO;

    @BeforeClass
    public void initTest() throws Exception {

        try {
            DAOUtils.initializeBatchDataSource(DB_NAME, H2_SCRIPT_NAME, H2_SCRIPT2_NAME);
        } catch (Exception e) {
            throw new IdentityOAuth2Exception("Error while initializing the data source", e);
        }
    }

    @BeforeMethod
    public void setUp() throws Exception {

        connection = DAOUtils.getConnection(DB_NAME);

        mockStatic(OAuthServerConfiguration.class);
        OAuthServerConfiguration mockOAuthServerConfiguration = mock(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockOAuthServerConfiguration);

        TokenPersistenceProcessor mockTokenPersistenceProcessor = mock(TokenPersistenceProcessor.class);
        when(mockOAuthServerConfiguration.getPersistenceProcessor()).thenReturn(mockTokenPersistenceProcessor);

        mockStatic(IdentityDatabaseUtil.class);
        mockStatic(OAuth2Util.class);
        mockStatic(IdentityUtil.class);

        when(mockOAuthServerConfiguration.isTokenCleanupEnabled()).thenReturn(true);

        accessTokenDAO = new AccessTokenDAOImpl();
    }

    @AfterMethod
    public void closeup() throws Exception {

        if (connection != null) {
            connection.close();
        }
    }

    @Test
    public void testGetAccessTokensByUserForOpenidScope_includeExpiredAccessTokensWithActiveRefreshToken()
            throws Exception {

        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);

        when(OAuth2Util.getTenantId(anyString())).thenReturn(1234);
        when(OAuth2Util.getTokenPartitionedSqlByUserStore(
                SQLQueries.GET_OPEN_ID_ACCESS_TOKEN_DATA_BY_AUTHZUSER, PRIMARY_USER_STORE))
                .thenReturn(SQLQueries.GET_OPEN_ID_ACCESS_TOKEN_DATA_BY_AUTHZUSER);
        // Simulate that the access token is expired.
        when(OAuth2Util.getTimeToExpire(1704103200000L, 3600000L)).thenReturn(-1000L);

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName(TEST_USER1);
        authenticatedUser.setUserStoreDomain(PRIMARY_USER_STORE);
        authenticatedUser.setTenantDomain(TEST_TENANT_DOMAIN);

        assertTrue(accessTokenDAO
                        .getAccessTokensByUserForOpenidScope(authenticatedUser, true)
                        .stream()
                        .anyMatch(token -> EXPIRED_TOKEN_ID.equals(token.getTokenId())),
                "Expired access token with active refresh token was not returned.");

        assertFalse(accessTokenDAO
                        .getAccessTokensByUserForOpenidScope(authenticatedUser, false)
                        .stream()
                        .anyMatch(token -> EXPIRED_TOKEN_ID.equals(token.getTokenId())),
                "Expired access token with active refresh token was returned.");
    }
}
