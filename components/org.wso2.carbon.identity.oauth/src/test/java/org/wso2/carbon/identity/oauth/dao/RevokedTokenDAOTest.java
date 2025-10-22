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
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.testng.annotations.AfterClass;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.RevokedTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.UUID;

import static org.mockito.Matchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.doNothing;
import static org.powermock.api.mockito.PowerMockito.doThrow;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants.ENTITY_ID_TYPE_USER_NAME;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RevokedTokenPersistenceSQLQueries.INSERT_REVOKED_TOKEN;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RevokedTokenPersistenceSQLQueries.INSERT_SUBJECT_ENTITY_REVOKED_EVENT;
import static org.wso2.carbon.identity.oauth2.dao.SQLQueries.RevokedTokenPersistenceSQLQueries.IS_REVOKED_TOKEN;

/*
 * Unit tests for RevokedTokenDAOTest.
 */
@PrepareForTest(
        {
                IdentityDatabaseUtil.class,
                OAuthServerConfiguration.class,
                IdentityUtil.class,
                OAuth2Util.class
        }
)
@PowerMockIgnore({"javax.*", "org.w3c.*", "org.xml.*"})
public class RevokedTokenDAOTest extends TestOAuthDAOBase {

    private static final String DELETE_ALL_REVOKED_TOKENS = "DELETE FROM IDN_OAUTH2_REVOKED_TOKENS WHERE 1=1";
    private static final String DELETE_ALL_REVOKED_ENTITIES = "DELETE FROM IDN_SUBJECT_ENTITY_REVOKED_EVENT WHERE 1=1";
    private static final String COUNT_ENTITIES = "SELECT count(*) FROM IDN_SUBJECT_ENTITY_REVOKED_EVENT WHERE " +
            "ENTITY_ID=? and TENANT_ID=?";
    private final RevokedTokenDAOImpl revokedTokenDAO = new RevokedTokenDAOImpl();
    private static final String DB_NAME = "RevokedTokenDAOTestDB";
    private static final String CONSUMER_KEY = "ca19a540f544777860e44e75f605d927";
    private static final String TOKEN_1 = "1234-1234-12345678-1234";
    private static final String ENTITY_ID = "9001-1009-09809809-0987";
    private static final String TOKEN_2 = "0550-2000-10983456-5646";
    private static final String UTC = "UTC";

    @Mock
    private OAuthServerConfiguration mockedServerConfig;


    @BeforeClass
    public void setUp() throws Exception {

        initMocks(this);
        initiateH2Base(DB_NAME, getFilePath("h2.sql"));
    }

    @AfterClass
    public void tearDown() throws Exception {

        closeH2Base(DB_NAME);
    }

    @BeforeMethod
    public void setUpMethod() {

        mockStatic(OAuthServerConfiguration.class);
        when(OAuthServerConfiguration.getInstance()).thenReturn(mockedServerConfig);
        mockStatic(OAuth2Util.class);
    }

    @AfterMethod
    public void tearDownMethod() throws Exception {

        cleanUpTables(DB_NAME);
    }

    @Test
    public void testCheckDefaultConfig() throws Exception {

        when(OAuth2Util.isKeepRevokedAccessTokenEnabled()).thenReturn(true);
        when(OAuth2Util.isAccessTokenPersistenceEnabled()).thenReturn(true);
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            assertFalse(revokedTokenDAO.isRevokedToken(TOKEN_1, CONSUMER_KEY),
                    "Revoked token check should return false for default config.");
            assertFalse(revokedTokenDAO.isTokenRevokedForSubjectEntity(ENTITY_ID, new Date()));
            revokedTokenDAO.addRevokedToken(TOKEN_1, CONSUMER_KEY, System.currentTimeMillis());
            assertFalse(assertTokenAddition(TOKEN_1, CONSUMER_KEY), "Revoked token should not be added " +
                    "when access token persistence is enabled.");
            long revocationTime = System.currentTimeMillis();
            revokedTokenDAO.revokeTokensBySubjectEvent(ENTITY_ID, ENTITY_ID_TYPE_USER_NAME,
                    revocationTime, -1234, 0);
            assertFalse(isEntityEntryAvailable(DB_NAME, ENTITY_ID, -1234),
                    "Revoked entity should not be added to db by default.");
        }
    }

    @Test
    public void testAddRevokedToken() throws Exception {

        when(OAuth2Util.isKeepRevokedAccessTokenEnabled()).thenReturn(true);
        when(OAuth2Util.isAccessTokenPersistenceEnabled()).thenReturn(false);
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            revokedTokenDAO.addRevokedToken(TOKEN_1, CONSUMER_KEY, System.currentTimeMillis());
            assertTrue(assertTokenAddition(TOKEN_1, CONSUMER_KEY), "Revoked token should be added successfully.");
        }
    }

    private boolean assertTokenAddition(String token, String consumerKey) {

        try (Connection connection = getConnection(DB_NAME);
             PreparedStatement preparedStatement = connection.prepareStatement(IS_REVOKED_TOKEN)) {
            preparedStatement.setString(1, token);
            preparedStatement.setString(2, consumerKey);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                return resultSet.next();
            }
        } catch (Exception e) {
            return false;
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testAddRevokedTokenWithExceptions() throws Exception {

        when(OAuth2Util.isKeepRevokedAccessTokenEnabled()).thenReturn(true);
        when(OAuth2Util.isAccessTokenPersistenceEnabled()).thenReturn(false);
        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(connection1);
            revokedTokenDAO.addRevokedToken(TOKEN_2, CONSUMER_KEY, System.currentTimeMillis());
        }
    }

    @Test
    public void testIsRevokedToken() throws Exception {

        when(OAuth2Util.isKeepRevokedAccessTokenEnabled()).thenReturn(true);
        when(OAuth2Util.isAccessTokenPersistenceEnabled()).thenReturn(false);
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            assertFalse(revokedTokenDAO.isRevokedToken(TOKEN_1, CONSUMER_KEY),
                    "Revoked token check should return false for non-existing token.");
            addToken(TOKEN_1, CONSUMER_KEY, System.currentTimeMillis());
            assertTrue(revokedTokenDAO.isRevokedToken(TOKEN_1, CONSUMER_KEY),
                    "Revoked token check should return true for existing token.");
        }
    }

    private void addToken(String token, String consumerKey, long expiryTime)  throws Exception {

        try (Connection connection = getConnection(DB_NAME);
             PreparedStatement preparedStatement = connection.prepareStatement(INSERT_REVOKED_TOKEN)) {
            preparedStatement.setString(1, UUID.randomUUID().toString());
            preparedStatement.setString(2, token);
            preparedStatement.setString(3, consumerKey);
            preparedStatement.setTimestamp(4, new Timestamp(expiryTime),
                    Calendar.getInstance(TimeZone.getTimeZone(UTC)));
            preparedStatement.executeUpdate();
            IdentityDatabaseUtil.commitTransaction(connection);
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIsRevokedTokenWithExceptions() throws Exception {

        when(OAuth2Util.isKeepRevokedAccessTokenEnabled()).thenReturn(true);
        when(OAuth2Util.isAccessTokenPersistenceEnabled()).thenReturn(false);

        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(connection1);
            revokedTokenDAO.isRevokedToken(TOKEN_1, CONSUMER_KEY);
        }
    }

    @Test
    public void testIsTokenRevokedForSubjectEntity() throws Exception {

        when(OAuth2Util.isKeepRevokedAccessTokenEnabled()).thenReturn(true);
        when(OAuth2Util.isAccessTokenPersistenceEnabled()).thenReturn(false);
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            assertFalse(revokedTokenDAO.isTokenRevokedForSubjectEntity(ENTITY_ID, new Date()),
                    "Revoked token check for subject entity should return false for non-existing entity.");
            long revocationTime = System.currentTimeMillis();
            addEntity(ENTITY_ID, ENTITY_ID_TYPE_USER_NAME, revocationTime);
            assertTrue(revokedTokenDAO.isTokenRevokedForSubjectEntity(ENTITY_ID, new Date(revocationTime - 1000L)),
                    "Revoked token check for subject entity should return true for existing entity.");
        }
    }

    private void addEntity(String entityId, String entityType, long revocationTime)  throws Exception {

        try (Connection connection = getConnection(DB_NAME);
             PreparedStatement ps1 = connection.prepareStatement(INSERT_SUBJECT_ENTITY_REVOKED_EVENT)) {
            ps1.setString(1, UUID.randomUUID().toString());
            ps1.setString(2, entityId);
            ps1.setString(3, entityType);
            ps1.setTimestamp(4, new Timestamp(revocationTime),
                    Calendar.getInstance(TimeZone.getTimeZone(UTC)));
            ps1.setInt(5, -1234);
            ps1.execute();
            IdentityDatabaseUtil.commitTransaction(connection);
        }
    }

    @Test(expectedExceptions = IdentityOAuth2Exception.class)
    public void testIsTokenRevokedForSubjectEntityWithExceptions() throws Exception {

        when(OAuth2Util.isKeepRevokedAccessTokenEnabled()).thenReturn(true);
        when(OAuth2Util.isAccessTokenPersistenceEnabled()).thenReturn(false);
        try (Connection connection = getConnection(DB_NAME)) {
            Connection connection1 = getExceptionThrowingConnection(connection);
            mockIdentityDataBaseUtilConnection(connection1);
            revokedTokenDAO.isTokenRevokedForSubjectEntity(ENTITY_ID, new Date());
        }
    }

    @Test
    public void testAddTokenRevokedForSubjectEntity() throws Exception {

        when(OAuth2Util.isKeepRevokedAccessTokenEnabled()).thenReturn(true);
        when(OAuth2Util.isAccessTokenPersistenceEnabled()).thenReturn(false);
        try (Connection connection = getConnection(DB_NAME)) {
            mockIdentityUtilDataBaseConnection(connection);
            long revocationTime = System.currentTimeMillis();
            revokedTokenDAO.revokeTokensBySubjectEvent(ENTITY_ID, ENTITY_ID_TYPE_USER_NAME,
                    revocationTime, -1234, 0);
            assertTrue(isEntityEntryAvailable(DB_NAME, ENTITY_ID, -1234),
                    "Revoked entity should be added successfully.");
            revokedTokenDAO.revokeTokensBySubjectEvent(ENTITY_ID, ENTITY_ID_TYPE_USER_NAME,
                    revocationTime + 1000L, -1234, 0);
            assertTrue(isEntityEntryAvailable(DB_NAME, ENTITY_ID, -1234),
                    "Revoked entity should be added successfully.");
        }
    }

    private boolean isEntityEntryAvailable(String databaseName,
                                   String entityId,
                                   int tenantId) throws Exception {

        try (Connection connection = getConnection(databaseName);
             PreparedStatement preparedStatement = connection.prepareStatement(COUNT_ENTITIES)) {
            preparedStatement.setString(1, entityId);
            preparedStatement.setInt(2, tenantId);
            try (ResultSet resultSet = preparedStatement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getInt(1) == 1;
                }
            }
        }
        return false;
    }

    private void mockIdentityDataBaseUtilConnection(Connection connection) {

        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection);
        when(IdentityDatabaseUtil.getDBConnection(true)).thenReturn(connection);
    }

    private void mockIdentityUtilDataBaseConnection(Connection connection) throws SQLException {

        Connection connection1 = spy(connection);
        doNothing().when(connection1).close();
        mockStatic(IdentityDatabaseUtil.class);
        when(IdentityDatabaseUtil.getDBConnection()).thenReturn(connection1);
        when(IdentityDatabaseUtil.getDBConnection(false)).thenReturn(connection1);
        when(IdentityDatabaseUtil.getDBConnection(true)).thenReturn(connection1);
    }

    private Connection getExceptionThrowingConnection(Connection connection) throws SQLException {

        // Spy the original connection to throw an exception during commit
        Connection exceptionThrowingConnection = spy(connection);
        doNothing().when(exceptionThrowingConnection).close();
        doThrow(new SQLException()).when(exceptionThrowingConnection).prepareStatement(anyString());
        return exceptionThrowingConnection;
    }

    /**
     * Cleans up the revoked tokens and entities tables.
     *
     * @param databaseName Name of the database to clean up.
     * @throws Exception If an error occurs while cleaning up the tables.
     */
    private void cleanUpTables(String databaseName) throws Exception {

        try (Connection connection = getConnection(databaseName);
             PreparedStatement preparedStatement = connection.prepareStatement((DELETE_ALL_REVOKED_ENTITIES))) {
            preparedStatement.executeUpdate();
        }
        try (Connection connection = getConnection(databaseName);
             PreparedStatement preparedStatement = connection.prepareStatement((DELETE_ALL_REVOKED_TOKENS))) {
            preparedStatement.executeUpdate();
        }
    }
}
