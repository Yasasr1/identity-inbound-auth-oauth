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

package org.wso2.carbon.identity.oauth.tokenprocessor;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.dao.RefreshTokenDAOImpl;
import org.wso2.carbon.identity.oauth2.dto.OAuthRevocationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.RefreshTokenValidationDataDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants.ENTITY_ID_TYPE_CLIENT_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants.ENTITY_ID_TYPE_USER_ID;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.NonPersistenceConstants.ENTITY_ID_TYPE_USER_NAME;

/**
 * This class provides the implementation for revoking access tokens and refresh tokens in the context of InMemory
 * token persistence. It is designed to handle token revocation requests and perform the necessary actions to mark
 * tokens as revoked. The class implements the OAuth2RevocationProcessor interface to offer the following
 * functionality:
 * - Revoking access tokens, marking them as revoked in the persistence layer.
 * - Revoking refresh tokens, marking them as revoked in the persistence layer.
 * - Handling both JWT and opaque token formats for refresh token revocation.
 * This class also handles token hashing, token state updates, and interaction with the invalid token persistence
 * service.
 */
public class HybridOAuth2RevocationProcessor implements OAuth2RevocationProcessor {

    private static final Log LOG = LogFactory.getLog(HybridOAuth2RevocationProcessor.class);
    private final DefaultOAuth2RevocationProcessor defaultOAuth2RevocationProcessor
            = new DefaultOAuth2RevocationProcessor();

    @Override
    public void revokeAccessToken(OAuthRevocationRequestDTO revokeRequestDTO, AccessTokenDO accessTokenDO)
            throws IdentityOAuth2Exception {

        if (OAuth2Util.isAccessTokenPersistenceEnabled()) {
            // If token persistence is enabled, we should not use this processor.
            // Instead, we should use the DefaultOAuth2RevocationProcessor.
            return;
        }

        if (LOG.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.ACCESS_TOKEN)) {
                LOG.debug(String.format("Revoking access token(hashed): %s",
                        DigestUtils.sha256Hex(accessTokenDO.getAccessToken())));
            } else {
                LOG.debug("Revoking access token.");
            }
        }

        if (accessTokenDO.isNotPersisted()) {
            // Token is non-persistent: update state and store in invalid token registry
            accessTokenDO.setTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);

            long expiryTime = accessTokenDO.getIssuedTime().getTime() + accessTokenDO.getValidityPeriodInMillis();

            OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO()
                    .addRevokedToken(
                            accessTokenDO.getAccessToken(),
                            accessTokenDO.getConsumerKey(),
                            expiryTime);
        } else {
            // Persistent token: revoke via default implementation.
            defaultOAuth2RevocationProcessor.revokeAccessToken(revokeRequestDTO, accessTokenDO);
        }
    }

    @Override
    public void revokeRefreshToken(OAuthRevocationRequestDTO revokeRequestDTO,
                                   RefreshTokenValidationDataDO refreshTokenDO) throws IdentityOAuth2Exception {

        if (OAuth2Util.isAccessTokenPersistenceEnabled()) {
            // If token persistence is enabled, we should not use this processor.
            // Instead, we should use the DefaultOAuth2RevocationProcessor.
            return;
        }
        String refreshTokenIdentifier = refreshTokenDO.getRefreshToken();
        if (LOG.isDebugEnabled()) {
            if (IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.REFRESH_TOKEN)) {
                LOG.debug(String.format("Revoking refresh token(hashed): %s",
                        DigestUtils.sha256Hex(refreshTokenIdentifier)));
            } else {
                LOG.debug("Revoking refresh token.");
            }
        }
        if (refreshTokenDO.isWithNotPersistedAT()) {
            refreshTokenDO.setRefreshTokenState(OAuthConstants.TokenStates.TOKEN_STATE_REVOKED);
            if (OAuth2Util.isRefreshTokenPersistenceEnabled()) {
                new RefreshTokenDAOImpl().revokeToken(refreshTokenDO.getRefreshToken());
            } else {

                long expiryTime = refreshTokenDO.getIssuedTime().getTime() + refreshTokenDO.getValidityPeriodInMillis();

                OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO()
                        .addRevokedToken(
                                refreshTokenDO.getRefreshToken(),
                                revokeRequestDTO.getConsumerKey(),
                                expiryTime);
            }
        } else {
            defaultOAuth2RevocationProcessor.revokeRefreshToken(revokeRequestDTO, refreshTokenDO);
        }
    }

    /**
     * Revokes all access and refresh tokens issued to a given user in a non-persistent token scenario.
     *
     * @param username          The username whose tokens should be revoked.
     * @param userStoreManager  The user store manager for retrieving user-specific metadata.
     * @return true if the revocation was successful, false otherwise.
     * @throws UserStoreException if an error occurs while interacting with the user store.
     */
    public boolean revokeTokens(String username, UserStoreManager userStoreManager) throws UserStoreException {

        // If token persistence is enabled, this processor should not be used.
        if (OAuth2Util.isAccessTokenPersistenceEnabled()) {
            return true;
        }

        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        String tenantDomain = IdentityTenantUtil.getTenantDomain(tenantId);
        long revocationTime = System.currentTimeMillis();

        Map<String, Object> params = new HashMap<>();
        params.put(NonPersistenceConstants.REVOCATION_TIME, revocationTime);
        params.put(NonPersistenceConstants.TENANT_DOMAIN, tenantDomain);
        params.put(NonPersistenceConstants.TENANT_ID, tenantId);
        params.put(NonPersistenceConstants.USERNAME, username);

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(username, tenantDomain, userStoreManager);
        boolean isUniqueUserIdEnabled = ((AbstractUserStoreManager) userStoreManager).isUniqueUserIdEnabled();

        String entityId;
        String entityType;

        if (isUniqueUserIdEnabled) {
            entityId = ((AbstractUserStoreManager) userStoreManager).getUserIDFromUserName(username);
            entityType = ENTITY_ID_TYPE_USER_ID;
        } else {
            entityId = authenticatedUser.toFullQualifiedUsername();
            entityType = ENTITY_ID_TYPE_USER_NAME;
        }

        params.put(NonPersistenceConstants.ENTITY_ID, entityId);
        params.put(NonPersistenceConstants.ENTITY_TYPE, entityType);

        // Invoke pre-revocation listeners
        OAuthUtil.invokePreRevocationBySystemListeners(entityId, params);

        try {
            // Revoke tokens for the user by storing revocation metadata
            OAuthTokenPersistenceFactory.getInstance()
                    .getRevokedTokenPersistenceDAO()
                    .revokeTokensBySubjectEvent(entityId, entityType, revocationTime, tenantId, 0);

            // Revoke refresh tokens and application tokens
            revokeRefreshTokenOfUser(authenticatedUser, tenantId, userStoreManager);
            revokeAppTokensOfUser(username, tenantDomain, tenantId, revocationTime);

        } catch (IdentityOAuth2Exception e) {
            LOG.error("Error while persisting revocation rules for user tokens.", e);
            return false;
        }

        // Invoke post-revocation listeners
        OAuthUtil.invokePostRevocationBySystemListeners(entityId, params);

        return true;
    }

    private AuthenticatedUser getAuthenticatedUser(String username, String tenantDomain,
                                                   UserStoreManager userStoreManager) {

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserStoreDomain(userStoreDomain);
        authenticatedUser.setTenantDomain(tenantDomain);
        authenticatedUser.setUserName(username);
        return authenticatedUser;
    }

    private void revokeRefreshTokenOfUser(AuthenticatedUser authenticatedUser,
                                          int tenantId, UserStoreManager userStoreManager)
            throws IdentityOAuth2Exception {

        String userStoreDomain = UserCoreUtil.getDomainName(userStoreManager.getRealmConfiguration());
        new RefreshTokenDAOImpl().revokeTokensByUser(authenticatedUser, tenantId, userStoreDomain);
    }

    /**
     * Revokes all application tokens owned by the user in a non-persistent token scenario.
     *
     * @param username       The username whose application tokens should be revoked.
     * @param tenantDomain   The tenant domain of the user.
     * @param tenantId       The tenant ID of the user.
     * @param revocationTime The time at which the revocation is performed.
     */
    private void revokeAppTokensOfUser(String username, String tenantDomain, int tenantId, long revocationTime) {

        // Get client ids for the apps owned by user since the 'sub' claim for these are the consumer key.
        // The app tokens for those consumer keys should also be revoked.
        OAuthAppDAO oAuthAppDAO = new OAuthAppDAO();
        try {
            OAuthAppDO[] oAuthAppDOs = oAuthAppDAO
                    .getOAuthConsumerAppsOfUser(username, tenantId);
            for (OAuthAppDO oAuthAppDO : oAuthAppDOs) {
                String consumerKey = oAuthAppDO.getOauthConsumerKey();
                Map<String, Object> revokeAppTokenParams = new HashMap<>();
                revokeAppTokenParams.put(NonPersistenceConstants.ENTITY_ID, consumerKey);
                revokeAppTokenParams.put(NonPersistenceConstants.ENTITY_TYPE,
                        ENTITY_ID_TYPE_CLIENT_ID);
                revokeAppTokenParams.put(NonPersistenceConstants.REVOCATION_TIME, revocationTime);
                revokeAppTokenParams.put(NonPersistenceConstants.TENANT_DOMAIN, tenantDomain);
                revokeAppTokenParams.put(NonPersistenceConstants.TENANT_ID, tenantId);
                OAuthUtil.invokePreRevocationBySystemListeners(consumerKey, revokeAppTokenParams);
                OAuthTokenPersistenceFactory.getInstance().getRevokedTokenPersistenceDAO().revokeTokensBySubjectEvent
                        (consumerKey, ENTITY_ID_TYPE_CLIENT_ID,
                                revocationTime, tenantId, 0);
                OAuthUtil.invokePostRevocationBySystemListeners(consumerKey, revokeAppTokenParams);
            }
        } catch (IdentityOAuthAdminException | IdentityOAuth2Exception e) {
            LOG.error("Error while persisting revoke rules for app tokens by user event.", e);
        }
    }
}
