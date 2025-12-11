/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com)
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

package org.wso2.carbon.identity.oauth.dao;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth2.dao.RefreshTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Set;
import java.util.TimeZone;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.AssertJUnit.assertEquals;

@PrepareForTest(
        {
                IdentityDatabaseUtil.class,
                OAuthServerConfiguration.class,
                IdentityUtil.class,
                OAuth2Util.class,
                OAuth2ServiceComponentHolder.class,
                IdentityTenantUtil.class
        }
)
public class RefreshTokenDAOImplTest extends TestOAuthDAOBase {

    private static final String DB_NAME = "REFRESH_TOKEN_DB";
    private static final String CLIENT_ID = "ca19a540f544777860e44e75f605d927";
    private static final String SECRET = "87n9a540f544777860e44e75f605d435";
    private static final String APP_NAME = "myApp";
    private static final String USER_NAME = "user1";
    private static final String APP_STATE = "ACTIVE";
    private static final String CALLBACK = "http://localhost:8080/redirect";
    private static final String BACKCHANNELLOGOUT_URL = "http://localhost:8080/backChannelLogout";

    @Mock
    private OAuthServerConfiguration mockedServerConfig;
    @Mock
    private ApplicationManagementService mockedApplicationManagementService;
    @Mock
    private ServiceProvider mockedServiceProvider;
    @Mock
    private LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig;
    @Mock
    TokenPersistenceProcessor hashingProcessor;

    private AccessTokenDO accessTokenDO;

    @BeforeClass
    public void setUp() throws Exception {

        initMocks(this);
        initiateH2Base(DB_NAME, getFilePath("refreshToken.sql"));
        createBaseOAuthApp(DB_NAME, CLIENT_ID, SECRET, USER_NAME, APP_NAME, CALLBACK, APP_STATE,
                BACKCHANNELLOGOUT_URL);
    }

    @AfterClass
    public void tearDown() throws Exception {

        cleanTables();
        closeH2Base(DB_NAME);
    }

    @BeforeMethod
    public void setUpMethod() throws Exception {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        mockStatic(OAuth2Util.class);
        mockStatic(IdentityDatabaseUtil.class);
        mockStatic(IdentityUtil.class);
        mockStatic(OAuth2ServiceComponentHolder.class);
        mockStatic(IdentityTenantUtil.class);
        when(OAuth2Util.isRefreshTokenPersistenceEnabled()).thenReturn(true);
        when(IdentityTenantUtil.getTenantDomain(-1234)).thenReturn("carbon.super");
        when(IdentityTenantUtil.getTenantId("carbon.super")).thenReturn(-1234);
        when(OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
        when(hashingProcessor.getProcessedClientId(anyString())).thenReturn("ca19a540f544777860e44e75f605d927");
        when(hashingProcessor.getPreprocessedClientId(anyString())).thenReturn("ca19a540f544777860e44e75f605d927");
        when(mockedServerConfig.getPersistenceProcessor()).thenReturn(hashingProcessor);

        when(OAuth2ServiceComponentHolder.getApplicationMgtService()).thenReturn(mockedApplicationManagementService);
        when(mockedApplicationManagementService.getServiceProviderByClientId(anyString(), anyString(), anyString()))
                .thenReturn(mockedServiceProvider);
        when(mockedServiceProvider.isSaasApp()).thenReturn(false);
        when(mockedServiceProvider.getLocalAndOutBoundAuthenticationConfig())
                .thenReturn(localAndOutboundAuthenticationConfig);

        when(localAndOutboundAuthenticationConfig.isUseUserstoreDomainInLocalSubjectIdentifier()).thenReturn(true);
        when(localAndOutboundAuthenticationConfig.isUseTenantDomainInLocalSubjectIdentifier()).thenReturn(true);
        when(OAuth2Util.getSanitizedUserStoreDomain(anyString())).thenReturn("SAMPLEDOMAIN");
        when(OAuth2Util.getAuthenticatedIDP(any())).thenReturn("LOCAL");

    }

    @Test
    public void testRefreshToken() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);

            RefreshTokenDAOImpl refreshTokenDAO = spy(new RefreshTokenDAOImpl());
            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");

            accessTokenDO = buildAccessTokenDO("dummyRefreshToken", "dummyTokenId", "");
            when(hashingProcessor.getProcessedAccessTokenIdentifier(anyString()))
                    .thenReturn(accessTokenDO.getRefreshToken());
            when(hashingProcessor.getProcessedRefreshToken(anyString())).thenReturn(accessTokenDO.getRefreshToken());
            AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();
            when(OAuth2Util.getUserStoreDomain(authenticatedUser)).thenReturn("SAMPLEDOMAIN");

            refreshTokenDAO.insertRefreshToken("sampleAccessToken", CLIENT_ID, accessTokenDO, "PRIMARY");

            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");

            when(OAuth2Util.getTenantDomain(-1234)).thenReturn("carbon.super");
            when(OAuth2Util.createAuthenticatedUser("sampleUser", "SAMPLEDOMAIN", "carbon.super", "LOCAL"))
                    .thenReturn(authenticatedUser);
            AccessTokenDO accessTokenDO1 = refreshTokenDAO.getRefreshToken("dummyRefreshToken");
            Assert.assertNotNull(accessTokenDO1);
            assertEquals("dummyTokenId", accessTokenDO1.getTokenId());
            assertEquals("authorization_code", accessTokenDO1.getGrantType());
            assertEquals("dummyRefreshToken", accessTokenDO1.getRefreshToken());
            assertEquals(CLIENT_ID, accessTokenDO1.getConsumerKey());
            assertEquals("ACTIVE", accessTokenDO1.getTokenState());

            refreshTokenDAO.revokeToken("dummyRefreshToken");
            AccessTokenDO accessTokenDO3 = refreshTokenDAO.getRefreshToken("dummyRefreshToken");
            Assert.assertNull(accessTokenDO3);
        }
    }

    @Test
    public void testActiveRefreshToken() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);

            RefreshTokenDAOImpl refreshTokenDAO = spy(new RefreshTokenDAOImpl());
            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");

            accessTokenDO = buildAccessTokenDO("dummyRefreshToken5", "dummyTokenId5",
                    "sample_scope");
            when(hashingProcessor.getProcessedAccessTokenIdentifier(anyString()))
                    .thenReturn(accessTokenDO.getRefreshToken());
            when(hashingProcessor.getProcessedRefreshToken(anyString())).thenReturn(accessTokenDO.getRefreshToken());
            AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();
            when(OAuth2Util.getUserStoreDomain(authenticatedUser)).thenReturn("SAMPLEDOMAIN");

            refreshTokenDAO.insertRefreshToken("sampleAccessToken", CLIENT_ID, accessTokenDO, "PRIMARY");

            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");

            when(OAuth2Util.getTenantDomain(-1234)).thenReturn("carbon.super");
            when(OAuth2Util.createAuthenticatedUser("sampleUser", "SAMPLEDOMAIN", "carbon.super", "LOCAL"))
                    .thenReturn(authenticatedUser);
            when(hashingProcessor.getPreprocessedRefreshToken("dummyRefreshToken5")).thenReturn("dummyRefreshToken5");

            AccessTokenDO accessTokenDO2 = refreshTokenDAO.getActiveRefreshToken(accessTokenDO.getConsumerKey(),
                    authenticatedUser, "SAMPLEDOMAIN", "sample_scope");
            Assert.assertNotNull(accessTokenDO2);
            assertEquals("dummyTokenId5", accessTokenDO2.getTokenId());
            assertEquals("dummyRefreshToken5", accessTokenDO2.getRefreshToken());
            assertEquals(CLIENT_ID, accessTokenDO2.getConsumerKey());
        }
    }

    @Test
    public void testRevokeApp() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);

            RefreshTokenDAOImpl refreshTokenDAO = spy(new RefreshTokenDAOImpl());
            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");

            accessTokenDO = buildAccessTokenDO("dummyRefreshToken2", "dummyTokenId2", "");
            refreshTokenDAO.insertRefreshToken("sampleAccessToken", CLIENT_ID, accessTokenDO, "PRIMARY");

            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");

            AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();
            when(OAuth2Util.getTenantDomain(-1234)).thenReturn("carbon.super");
            when(OAuth2Util.createAuthenticatedUser("sampleUser", "sampleDomain", "carbon.super", "LOCAL"))
                    .thenReturn(authenticatedUser);
            refreshTokenDAO.revokeTokensForApp(CLIENT_ID);
            AccessTokenDO accessTokenDO1 = refreshTokenDAO.getRefreshToken("dummyRefreshToken2");
            Assert.assertNull(accessTokenDO1);
        }
    }

    @Test
    public void testRevokeUser() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);

            RefreshTokenDAOImpl refreshTokenDAO = spy(new RefreshTokenDAOImpl());
            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");

            accessTokenDO = buildAccessTokenDO("dummyRefreshToken8", "dummyTokenId8", "test_scope");
            refreshTokenDAO.insertRefreshToken("sampleAccessToken", CLIENT_ID, accessTokenDO, "PRIMARY");

            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");

            AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();
            when(OAuth2Util.getTenantDomain(-1234)).thenReturn("carbon.super");
            when(OAuth2Util.createAuthenticatedUser("sampleUser", "sampleDomain", "carbon.super", "LOCAL"))
                    .thenReturn(authenticatedUser);
            refreshTokenDAO.revokeTokensByUser(authenticatedUser, -1234, "sampleDomain");
            AccessTokenDO accessTokenDO1 = refreshTokenDAO.getRefreshToken("dummyRefreshToken8");
            Assert.assertNull(accessTokenDO1);
        }
    }

    @Test
    public void testGetRefreshTokensByUserForOpenidScope() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);

            RefreshTokenDAOImpl refreshTokenDAO = spy(new RefreshTokenDAOImpl());
            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");

            accessTokenDO = buildAccessTokenDO("dummyRefreshToken3", "dummyTokenId3", "openid");
            AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();
            when(OAuth2Util.getUserStoreDomain(authenticatedUser)).thenReturn("SAMPLEDOMAIN");
            refreshTokenDAO.insertRefreshToken("sampleAccessToken", CLIENT_ID, accessTokenDO, "PRIMARY");

            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");

            when(OAuth2Util.getTenantDomain(-1234)).thenReturn("carbon.super");
            when(OAuth2Util.createAuthenticatedUser("sampleUser", "sampleDomain", "carbon.super", "LOCAL"))
                    .thenReturn(authenticatedUser);
            when(IdentityUtil.isUserStoreInUsernameCaseSensitive(anyString())).thenReturn(true);
            Set<AccessTokenDO> accessTokenDOSet
                    = refreshTokenDAO.getRefreshTokensByUserForOpenidScope(authenticatedUser);
            Assert.assertFalse(accessTokenDOSet.isEmpty());
            refreshTokenDAO.revokeToken("dummyRefreshToken3");
        }
    }

    @Test
    public void testRotateRefreshToken() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            cleanTables();

            RefreshTokenDAOImpl refreshTokenDAO = spy(new RefreshTokenDAOImpl());
            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");

            accessTokenDO = buildAccessTokenDO("dummyRefreshToken4", "dummyTokenId4", "internal_user_mgt_update");
            when(hashingProcessor.getProcessedAccessTokenIdentifier(anyString()))
                    .thenReturn(accessTokenDO.getRefreshToken());
            when(hashingProcessor.getProcessedRefreshToken(anyString())).thenReturn(accessTokenDO.getRefreshToken());
            AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();
            when(OAuth2Util.getUserStoreDomain(authenticatedUser)).thenReturn("SAMPLEDOMAIN");

            refreshTokenDAO.insertRefreshToken("sampleAccessToken", CLIENT_ID, accessTokenDO, "PRIMARY");

            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");
            when(OAuth2Util.getTenantId("carbon.super")).thenReturn(-1234);
            when(OAuth2Util.getTenantDomain(-1234)).thenReturn("carbon.super");
            when(OAuth2Util.createAuthenticatedUser("sampleUser", "SAMPLEDOMAIN", "carbon.super", "LOCAL"))
                    .thenReturn(authenticatedUser);

            accessTokenDO = buildAccessTokenDO("dummyRefreshToken5", "dummyTokenId5", "internal_user_mgt_update");
            when(hashingProcessor.getProcessedAccessTokenIdentifier(anyString()))
                    .thenReturn(accessTokenDO.getRefreshToken());
            when(hashingProcessor.getProcessedRefreshToken(anyString())).thenReturn(accessTokenDO.getRefreshToken());
            refreshTokenDAO.invalidateAndCreateNewRefreshToken("dummyTokenId4",
                    "INACTIVE", CLIENT_ID, accessTokenDO, "PRIMARY");
            assertEquals("INACTIVE", getRefreshTokenState("dummyTokenId4"));

            RefreshTokenValidationDataDO accessTokenDO1 = refreshTokenDAO.validateRefreshToken(CLIENT_ID,
                    "dummyRefreshToken5");
            Assert.assertNotNull(accessTokenDO1);
            assertEquals("dummyTokenId5", accessTokenDO1.getTokenId());
            assertEquals("authorization_code", accessTokenDO1.getGrantType());
            assertEquals("dummyRefreshToken5", accessTokenDO1.getRefreshToken());

            refreshTokenDAO.revokeToken("dummyRefreshToken5");
            AccessTokenDO accessTokenDO2 = refreshTokenDAO.getRefreshToken("dummyRefreshToken5");
            Assert.assertNull(accessTokenDO2);
        }
    }

    @Test
    public void testGetInvalidRefreshToken() throws Exception {

        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            TokenPersistenceProcessor hashingProcessor = mock(HashingPersistenceProcessor.class);
            when(hashingProcessor.getProcessedRefreshToken(anyString())).thenReturn("hashedRefreshToken");

            RefreshTokenDAOImpl refreshTokenDAO = spy(new RefreshTokenDAOImpl());
            doReturn(hashingProcessor).when(refreshTokenDAO, "getHashingPersistenceProcessor");
            AccessTokenDO accessTokenDO1 = refreshTokenDAO.getRefreshToken("invalidRefreshToken");
            Assert.assertNull(accessTokenDO1);
        }
    }

    private AccessTokenDO buildAccessTokenDO(String refreshToken, String tokenId, String scope) {

        AccessTokenDO tokenDO = new AccessTokenDO();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("sampleUser");
        authenticatedUser.setUserStoreDomain("sampleDomain");
        authenticatedUser.setTenantDomain("carbon.super");
        authenticatedUser.setAuthenticatedSubjectIdentifier("sampleUser");
        authenticatedUser.setUserId("sampleId");
        tokenDO.setConsumerKey(CLIENT_ID);
        tokenDO.setScope(new String[]{scope});
        tokenDO.setAccessToken("sampleAccessToken");
        tokenDO.setAuthzUser(authenticatedUser);
        tokenDO.setRefreshToken(refreshToken);
        tokenDO.setTokenId(tokenId);
        long currentTimeInMillis = Calendar.getInstance(TimeZone.getTimeZone("UTC")).getTimeInMillis();
        tokenDO.setIssuedTime(new Timestamp(currentTimeInMillis));
        tokenDO.setValidityPeriodInMillis(3600000L);
        tokenDO.setTokenType("JWT");
        tokenDO.setRefreshTokenIssuedTime(new Timestamp(currentTimeInMillis));
        tokenDO.setRefreshTokenValidityPeriodInMillis(3600000L);
        tokenDO.setNotPersisted(true);
        tokenDO.setTenantID(1);
        tokenDO.setTokenState("ACTIVE");
        tokenDO.setGrantType("authorization_code");
        tokenDO.setIsConsentedToken(true);
        return tokenDO;
    }

    private void mockIdentityUtilDataBaseConnection(Connection connection) throws SQLException {

        Connection connection1 = spy(connection);
        doNothing().when(connection1).close();
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection1);
        when(IdentityDatabaseUtil.getDBConnection(true)).thenReturn(connection1);
    }

    private String getRefreshTokenState(String tokenId) throws Exception {

        String query = "SELECT TOKEN_STATE FROM IDN_OAUTH2_REFRESH_TOKEN WHERE REFRESH_TOKEN_ID = ?";
        try (Connection connection = getConnection(RefreshTokenDAOImplTest.DB_NAME);
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, tokenId);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                while (resultSet.next()) {
                    return resultSet.getString("TOKEN_STATE");
                }
                return null;
            }
        }
    }

    private void cleanTables() throws Exception {

        String query = "DELETE FROM IDN_OAUTH2_REFRESH_TOKEN WHERE 1=1";
        try (Connection connection = getConnection(RefreshTokenDAOImplTest.DB_NAME);
             PreparedStatement preparedStatement = connection.prepareStatement((query))) {
            preparedStatement.executeUpdate();
        }
    }
}
