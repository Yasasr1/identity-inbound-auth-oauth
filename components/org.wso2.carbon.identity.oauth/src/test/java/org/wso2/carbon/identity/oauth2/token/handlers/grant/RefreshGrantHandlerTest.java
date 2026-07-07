/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.oauth2.token.handlers.grant;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementServiceImpl;
import org.wso2.carbon.identity.application.mgt.internal.ApplicationManagementServiceComponent;
import org.wso2.carbon.identity.application.mgt.internal.ApplicationManagementServiceComponentHolder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.common.testng.WithH2Database;
import org.wso2.carbon.identity.common.testng.WithRealmService;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.bindings.TokenBinding;
import org.wso2.carbon.identity.test.common.testng.utils.MockAuthenticatedUser;
import org.wso2.carbon.identity.testutil.Whitebox;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.REQUEST_BINDING_TYPE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_ACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_EXPIRED;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.TokenStates.TOKEN_STATE_INACTIVE;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.UNASSIGNED_VALIDITY_PERIOD;

/**
 * Test class for RefreshGrantHandler test cases.
 */
@WithCarbonHome
@WithRealmService(injectToSingletons = { OAuthComponentServiceHolder.class,
        ApplicationManagementServiceComponentHolder.class })
@WithH2Database(files = { "dbScripts/identity.sql" })
public class RefreshGrantHandlerTest {

    private static final String TEST_USER_ID = "testUser";
    private static final String TEST_USER_DOMAIN = "testDomain";
    private RefreshGrantHandler refreshGrantHandler;
    private AuthenticatedUser authenticatedUser;
    private String[] scopes;

    @BeforeClass
    protected void setUp() throws Exception {
        OAuth2ServiceComponentHolder.setApplicationMgtService(ApplicationManagementServiceImpl.getInstance());
        authenticatedUser = new MockAuthenticatedUser(TEST_USER_ID);
        authenticatedUser.setUserStoreDomain(TEST_USER_DOMAIN);
        scopes = new String[] { "scope1", "scope2" };
    }

    @BeforeMethod
    protected void setUpMethod() throws Exception {

        ApplicationManagementServiceComponent applicationManagementServiceComponent =
                new ApplicationManagementServiceComponent();
        Whitebox.invokeMethod(applicationManagementServiceComponent, "buildFileBasedSPList", null);
    }

    @DataProvider(name = "GetValidateGrantData")
    public Object[][] validateGrantData() {

        return new Object[][] {
                { "clientId1" },
                { "clientId2" },
                { "clientId2" }
        };
    }

    @Test(dataProvider = "GetValidateGrantData")
    public void testValidateGrant(String clientId)
            throws Exception {

        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        oAuthAppDAO.removeConsumerApplication(clientId);

        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setGrantTypes("implicit");
        oAuthAppDO.setOauthConsumerKey(clientId);
        oAuthAppDO.setUser(authenticatedUser);
        oAuthAppDO.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);

        oAuthAppDAO.addOAuthApplication(oAuthAppDO);

        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(clientId);
        tokenReqDTO.setRefreshToken("refreshToken1");
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        boolean isValid = refreshGrantHandler.validateGrant(tokenReqMessageContext);
        assertTrue(isValid, "Refresh token validation should be successful.");
    }

    @DataProvider(name = "validateGrantExceptionData")
    public Object[][] validateGrantExceptionData() {

        List<AccessTokenDO> accessTokenDOS = new ArrayList<>();
        AccessTokenDO accessTokenDO1 = new AccessTokenDO();
        accessTokenDO1.setTokenState(TOKEN_STATE_ACTIVE);
        accessTokenDO1.setRefreshToken("refreshToken1");

        AccessTokenDO accessTokenDO2 = new AccessTokenDO();
        accessTokenDO2.setTokenState(TOKEN_STATE_EXPIRED);
        accessTokenDO2.setRefreshToken("refreshToken2");

        accessTokenDOS.add(accessTokenDO1);
        accessTokenDOS.add(accessTokenDO2);

        return new Object[][] { { "clientId1", "refreshToken1", "accessToken1", TOKEN_STATE_INACTIVE, accessTokenDOS },
                { "clientId1", "refreshToken3", "accessToken1", TOKEN_STATE_EXPIRED, accessTokenDOS },
                { "clientId1", "refreshToken3", "accessToken1", TOKEN_STATE_EXPIRED, null },
                { "clientId1", "refreshToken1", null, null, accessTokenDOS }, };
    }

    @Test(dataProvider = "validateGrantExceptionData", expectedExceptions = IdentityOAuth2Exception.class)
    public void testValidateGrantForException(String clientId, String refreshToken, String accessToken,
            String tokenState, Object accessTokenObj) throws Exception {

        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(clientId);
        tokenReqDTO.setRefreshToken(refreshToken);
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);

        refreshGrantHandler.validateGrant(tokenReqMessageContext);
        Assert.fail("Authenticated user cannot be null.");
    }

    @Test(dataProvider = "GetTokenIssuerData")
    public void testIssue(Long userAccessTokenExpiryTime, Long validityPeriod, String renewRefreshToken,
                          String clientId) throws Exception {

        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        oAuthAppDAO.removeConsumerApplication(clientId);
        OAuthAppDO oAuthAppDO = new OAuthAppDO();
        oAuthAppDO.setUserAccessTokenExpiryTime(userAccessTokenExpiryTime);
        oAuthAppDO.setRefreshTokenExpiryTime(userAccessTokenExpiryTime);
        oAuthAppDO.setUser(authenticatedUser);
        oAuthAppDO.setOauthConsumerKey(clientId);
        oAuthAppDO.setOauthVersion(OAuthConstants.OAuthVersions.VERSION_2);
        oAuthAppDO.setRenewRefreshTokenEnabled(renewRefreshToken);
        oAuthAppDAO.addOAuthApplication(oAuthAppDO);

        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setClientId(clientId);
        tokenReqDTO.setRefreshToken("refreshToken1");
        tokenReqDTO.setScope(scopes);

        RefreshTokenValidationDataDO oldAccessToken = new RefreshTokenValidationDataDO();
        oldAccessToken.setTokenId("tokenId");
        oldAccessToken.setAccessToken("oldAccessToken");

        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenReqMessageContext.addProperty("previousAccessToken", oldAccessToken);
        tokenReqMessageContext.setAuthorizedUser(authenticatedUser);
        tokenReqMessageContext.setValidityPeriod(validityPeriod);
        tokenReqMessageContext.setScope(scopes);

        OAuth2AccessTokenRespDTO actual = refreshGrantHandler.issue(tokenReqMessageContext);
        assertFalse(actual.isError());
        assertNotNull(actual.getRefreshToken());
        if (Objects.equals(renewRefreshToken, "true") || (renewRefreshToken == null)) {
            assertNotEquals("refreshToken1", actual.getRefreshToken());
        } else {
            assertEquals("refreshToken1", actual.getRefreshToken());
        }
    }

    @Test(dataProvider = "GetValidateScopeData")
    public void validateScope(String[] requestedScopes, String[] grantedScopes, boolean expected, String message)
            throws Exception {

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        tokenReqDTO.setScope(requestedScopes);
        tokenReqDTO.setClientId("clientId1");
        tokenReqDTO.setRefreshToken("refreshToken1");
        tokenReqDTO.setGrantType("refreshTokenGrant");
        OAuthTokenReqMessageContext tokenReqMessageContext = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokenReqMessageContext.setScope(grantedScopes);

        refreshGrantHandler = new RefreshGrantHandler();
        refreshGrantHandler.init();
        boolean actual = refreshGrantHandler.validateScope(tokenReqMessageContext);
        assertEquals(actual, expected, message);
    }

    /**
     * When {@code renew_token_without_revoking_existing} is enabled and refresh_token is an allowed grant type, the
     * context carries a {@link TokenBinding} of type {@code REQUEST_BINDING_TYPE}. If the new AccessTokenDO has no
     * binding yet, {@code handleRequestBinding} must copy the request binding from the context onto the AccessTokenDO
     * so the persisted token gets a distinct TOKEN_BINDING_REF (guards against the CON_APP_KEY collision / HTTP 500).
     */
    @Test
    public void testHandleRequestBindingCopiesRequestBindingWhenAccessTokenBindingIsNull() throws Exception {

        refreshGrantHandler = new RefreshGrantHandler();

        AccessTokenDO accessTokenDO = new AccessTokenDO();
        assertNull(accessTokenDO.getTokenBinding(), "Precondition: AccessTokenDO should start with a null binding.");

        TokenBinding requestBinding = new TokenBinding(REQUEST_BINDING_TYPE, "requestBindingRef");
        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokReqMsgCtx.setTokenBinding(requestBinding);

        Whitebox.invokeMethod(refreshGrantHandler, "handleRequestBinding", accessTokenDO, tokReqMsgCtx);

        assertNotNull(accessTokenDO.getTokenBinding(),
                "Request binding should have been copied onto the AccessTokenDO.");
        assertSame(accessTokenDO.getTokenBinding(), requestBinding,
                "AccessTokenDO should carry the exact request binding instance from the context.");
        assertEquals(accessTokenDO.getTokenBinding().getBindingType(), REQUEST_BINDING_TYPE,
                "Copied binding must be of type REQUEST_BINDING_TYPE.");
    }

    /**
     * If the new AccessTokenDO already carries a binding (e.g. a real cookie / certificate / SSO-session binding),
     * {@code handleRequestBinding} must early-return and leave it untouched — a genuine binding is never overwritten
     * by the request binding.
     */
    @Test
    public void testHandleRequestBindingDoesNotOverrideExistingBinding() throws Exception {

        refreshGrantHandler = new RefreshGrantHandler();

        TokenBinding existingBinding = new TokenBinding("cookie", "existingCookieRef");
        AccessTokenDO accessTokenDO = new AccessTokenDO();
        accessTokenDO.setTokenBinding(existingBinding);

        TokenBinding requestBinding = new TokenBinding(REQUEST_BINDING_TYPE, "requestBindingRef");
        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokReqMsgCtx.setTokenBinding(requestBinding);

        Whitebox.invokeMethod(refreshGrantHandler, "handleRequestBinding", accessTokenDO, tokReqMsgCtx);

        assertSame(accessTokenDO.getTokenBinding(), existingBinding,
                "An existing binding on the AccessTokenDO must not be overwritten by the request binding.");
        assertEquals(accessTokenDO.getTokenBinding().getBindingType(), "cookie",
                "The existing binding type must remain unchanged.");
    }

    /**
     * When the context binding is present but is NOT of type {@code REQUEST_BINDING_TYPE} (the opaque-issuer / other
     * binding path), {@code handleRequestBinding} must be a no-op — the AccessTokenDO binding stays null so no spurious
     * binding is introduced (the token is persisted with TOKEN_BINDING_REF = 'NONE' as before).
     */
    @Test
    public void testHandleRequestBindingIsNoOpWhenContextBindingIsNotRequestType() throws Exception {

        refreshGrantHandler = new RefreshGrantHandler();

        AccessTokenDO accessTokenDO = new AccessTokenDO();

        TokenBinding nonRequestBinding = new TokenBinding("sso-session", "ssoSessionRef");
        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(tokenReqDTO);
        tokReqMsgCtx.setTokenBinding(nonRequestBinding);

        Whitebox.invokeMethod(refreshGrantHandler, "handleRequestBinding", accessTokenDO, tokReqMsgCtx);

        assertNull(accessTokenDO.getTokenBinding(),
                "A non-request context binding must not be copied onto the AccessTokenDO.");
    }

    /**
     * Negative / edge case: when the context has no token binding at all (null), {@code handleRequestBinding} must not
     * throw an NPE and must leave the AccessTokenDO binding null.
     */
    @Test
    public void testHandleRequestBindingIsNoOpWhenContextBindingIsNull() throws Exception {

        refreshGrantHandler = new RefreshGrantHandler();

        AccessTokenDO accessTokenDO = new AccessTokenDO();

        OAuth2AccessTokenReqDTO tokenReqDTO = new OAuth2AccessTokenReqDTO();
        OAuthTokenReqMessageContext tokReqMsgCtx = new OAuthTokenReqMessageContext(tokenReqDTO);
        assertNull(tokReqMsgCtx.getTokenBinding(), "Precondition: context token binding should be null.");

        Whitebox.invokeMethod(refreshGrantHandler, "handleRequestBinding", accessTokenDO, tokReqMsgCtx);

        assertNull(accessTokenDO.getTokenBinding(),
                "A null context binding must leave the AccessTokenDO binding null without throwing.");
    }

    @DataProvider(name = "GetTokenIssuerData")
    public Object[][] tokenIssuerData() {

        return new Object[][] {
                { 0L, UNASSIGNED_VALIDITY_PERIOD, "true", "clientId1" },
                { 20L, UNASSIGNED_VALIDITY_PERIOD, "true", "clientId2" },
                { 20L, 20L, "true", "clientId3" },
                { 0L, UNASSIGNED_VALIDITY_PERIOD, "true", "clientId4" },
                { 20L, 20L, "false", "clientId5" },
                { 20L, 20L, null, "clientId6" },
                { 20L, 20L, "true", "clientId7" } };
    }

    @DataProvider(name = "GetValidateScopeData")
    public Object[][] validateScopeData() {

        String[] requestedScopes = new String[2];
        requestedScopes[0] = "scope1";
        requestedScopes[1] = "scope2";

        String[] grantedScopes = new String[1];
        grantedScopes[0] = "scope1";

        String[] grantedScopesWithRequestedScope = new String[1];
        grantedScopesWithRequestedScope[0] = "scope1";
        grantedScopesWithRequestedScope[0] = "scope2";

        return new Object[][] { { requestedScopes, grantedScopes, false, "scope validation should fail." },
                { requestedScopes, grantedScopesWithRequestedScope, false, "scope validation should fail." },
                { requestedScopes, new String[0], false, "scope validation should fail." },
                { new String[] { "scope_not_granted" }, grantedScopes, false, "scope validation should fail." }, };
    }
}
