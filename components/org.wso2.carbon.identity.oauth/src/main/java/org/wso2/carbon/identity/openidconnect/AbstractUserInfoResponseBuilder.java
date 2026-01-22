/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.openidconnect;

import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCache;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry;
import org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheKey;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.user.UserInfoEndpointException;
import org.wso2.carbon.identity.oauth.user.UserInfoResponseBuilder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.RequestObjectException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.internal.OpenIDConnectServiceComponentHolder;
import org.wso2.carbon.identity.openidconnect.model.RequestedClaim;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.apache.commons.collections.CollectionUtils.isNotEmpty;
import static org.apache.commons.lang.StringUtils.isNotEmpty;
import static org.wso2.carbon.identity.oauth.common.OAuthConstants.OAuth20Params.USERINFO;

/**
 * Abstract user info response builder.
 */
public abstract class AbstractUserInfoResponseBuilder implements UserInfoResponseBuilder {

    private static final Log log = LogFactory.getLog(AbstractUserInfoResponseBuilder.class);

    @Override
    public String getResponseString(OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException, OAuthSystemException {

        // To improve performance, skipping indirect revocation check here.
        Optional<AccessTokenDO> optionalAccessTokenDO = OAuth2Util.getAccessTokenDO(tokenResponse, false);
        if (!optionalAccessTokenDO.isPresent()) {
            throw new IllegalArgumentException(OAuth2Util.ACCESS_TOKEN_IS_NOT_ACTIVE_ERROR_MESSAGE);

        }
        AccessTokenDO accessTokenDO = optionalAccessTokenDO.get();
        String clientId = accessTokenDO.getConsumerKey();
        String spTenantDomain = getServiceProviderTenantDomain(clientId);
        // Retrieve user claims.
        Map<String, Object> userClaims = retrieveUserClaims(tokenResponse);
        Map<String, Object> filteredUserClaims = filterOIDCClaims(tokenResponse, clientId, spTenantDomain, userClaims,
                accessTokenDO);

        // Handle subject claim.
        String subjectClaim = getSubjectClaim(accessTokenDO);
        filteredUserClaims.put(OAuth2Util.SUB, subjectClaim);

        return buildResponse(tokenResponse, spTenantDomain, filteredUserClaims);
    }

    private Map<String, Object> filterOIDCClaims(OAuth2TokenValidationResponseDTO tokenResponse,
                                                 String clientId,
                                                 String spTenantDomain,
                                                 Map<String, Object> userClaims, AccessTokenDO accessTokenDO)
            throws OAuthSystemException, UserInfoEndpointException {

        String accessToken = accessTokenDO.getAccessToken();

        if (MapUtils.isEmpty(userClaims)) {
            if (log.isDebugEnabled()) {
                AuthenticatedUser authenticatedUser = OAuth2Util.getAuthenticatedUser(accessTokenDO);
                log.debug("No user claims available to be filtered for user: " +
                        authenticatedUser.toFullQualifiedUsername() + " for client_id: " + clientId +
                        " of tenantDomain: " + spTenantDomain);
            }
            return new HashMap<>();
        }

        // Filter user claims based on the requested scopes
        Map<String, Object> userClaimsFilteredByScope =
                getUserClaimsFilteredByScope(tokenResponse, userClaims, tokenResponse.getScope(), clientId,
                        spTenantDomain);

        // Handle essential claims
        Map<String, Object> essentialClaims = getEssentialClaims(userClaims, accessTokenDO);
        userClaimsFilteredByScope.putAll(essentialClaims);

        if (!accessTokenDO.isNotPersisted()) {
            // If the access token is not persisted, we cannot retrieve essential claims from the request object.
            //Handle essential claims of the request object for persisted token
            Map<String, Object> filteredClaimsFromRequestObject = filterClaimsFromRequestObject(userClaims,
                    accessToken);
            userClaimsFilteredByScope.putAll(filteredClaimsFromRequestObject);
        }

        // Filter the user claims based on user consent
        AuthenticatedUser authenticatedUser = OAuth2Util.getAuthenticatedUser(accessTokenDO);
        return getUserClaimsFilteredByConsent(tokenResponse, userClaimsFilteredByScope, authenticatedUser, clientId,
                spTenantDomain, accessTokenDO);
    }

    private String getGrantType(OAuth2TokenValidationResponseDTO tokenResponse, AccessTokenDO accessTokenDO)
            throws UserInfoEndpointException {

        if (accessTokenDO != null && accessTokenDO.isNotPersisted()) {
            return accessTokenDO.getGrantType();
        }
        try {
            return OAuth2Util.getAccessTokenDOfromTokenIdentifier(
                    OAuth2Util.getAccessTokenIdentifier(tokenResponse)).getGrantType();
        } catch (IdentityOAuth2Exception e) {
            throw new UserInfoEndpointException(
                    "Error while retrieving access token information to derive the grant type." , e);
        }
    }

    private Map<String, Object> filterClaimsFromRequestObject(Map<String, Object> userAttributes,
                                                              String token) throws OAuthSystemException {
        try {
            List<RequestedClaim> requestedClaims = OpenIDConnectServiceComponentHolder.getRequestObjectService().
                    getRequestedClaimsForUserInfo(token);
            return OpenIDConnectServiceComponentHolder.getInstance()
                    .getHighestPriorityOpenIDConnectClaimFilter()
                    .getClaimsFilteredByEssentialClaims(userAttributes, requestedClaims);
        } catch (RequestObjectException e) {
            throw new OAuthSystemException("Unable to retrieve requested claims from Request Object." + e);
        }


    }

    /**
     * Get the 'sub' claim. By append the userStoreDomain or tenantDomain for local users based on the Service
     * Provider's local and outbound authentication configurations.
     *
     * @param userClaims
     * @param clientId
     * @param spTenantDomain
     * @param tokenResponse
     * @return
     * @throws UserInfoEndpointException
     * @throws OAuthSystemException
     */
    protected String getSubjectClaim(Map<String, Object> userClaims,
                                     String clientId,
                                     String spTenantDomain,
                                     OAuth2TokenValidationResponseDTO tokenResponse)
            throws UserInfoEndpointException, OAuthSystemException {

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(OAuth2Util.getAccessTokenIdentifier(tokenResponse));
        return authenticatedUser.getAuthenticatedSubjectIdentifier();
    }


    protected String getSubjectClaim(AccessTokenDO accessTokenDO) {

        AuthenticatedUser authenticatedUser = OAuth2Util.getAuthenticatedUser(accessTokenDO);
        return authenticatedUser.getAuthenticatedSubjectIdentifier();
    }

    /**
     * Filter user claims requested by the Service Provider based on the requested scopes.
     *
     * @param userClaims
     * @param requestedScopes
     * @param clientId
     * @param tenantDomain
     * @return
     */
    protected Map<String, Object> getUserClaimsFilteredByScope(OAuth2TokenValidationResponseDTO validationResponseDTO,
                                                               Map<String, Object> userClaims,
                                                               String[] requestedScopes,
                                                               String clientId,
                                                               String tenantDomain) throws UserInfoEndpointException {

        return OpenIDConnectServiceComponentHolder.getInstance()
                .getHighestPriorityOpenIDConnectClaimFilter()
                .getClaimsFilteredByOIDCScopes(userClaims, requestedScopes, clientId, tenantDomain);
    }

    /**
     * Filter user claims requested by the Service Provider based on the requested scopes.
     *
     * @param userClaims
     * @param user
     * @param clientId
     * @param tenantDomain
     * @return
     */
    protected Map<String, Object> getUserClaimsFilteredByConsent(OAuth2TokenValidationResponseDTO validationResponseDTO,
                                                                 Map<String, Object> userClaims,
                                                                 AuthenticatedUser user,
                                                                 String clientId,
                                                                 String tenantDomain) throws UserInfoEndpointException {

        String grantType = getGrantType(validationResponseDTO, null);
        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            try {
                // Get the Access Token details from the database/cache to check if the token is consented or not.
                String accessToken = validationResponseDTO.getAuthorizationContextToken().getTokenString();
                AccessTokenDO accessTokenDO = OAuth2ServiceComponentHolder.getInstance().getTokenProvider()
                        .getVerifiedAccessToken(accessToken, false);
                boolean isConsentedToken = accessTokenDO.isConsentedToken();
                return OIDCClaimUtil.filterUserClaimsBasedOnConsent(userClaims, user, clientId, tenantDomain, grantType,
                        getServiceProvider(tenantDomain, clientId), isConsentedToken);
            } catch (IdentityOAuth2Exception e) {
                throw new UserInfoEndpointException("An error occurred while fetching the access token details.", e);
            }
        }
        return OIDCClaimUtil.filterUserClaimsBasedOnConsent(userClaims, user, clientId, tenantDomain, grantType,
                getServiceProvider(tenantDomain, clientId));
    }

    protected Map<String, Object> getUserClaimsFilteredByConsent(OAuth2TokenValidationResponseDTO validationResponseDTO,
                                                                 Map<String, Object> userClaims,
                                                                 AuthenticatedUser user,
                                                                 String clientId,
                                                                 String tenantDomain, AccessTokenDO accessTokenDO)
            throws UserInfoEndpointException {

        String grantType = getGrantType(validationResponseDTO, accessTokenDO);
        if (OAuth2ServiceComponentHolder.isConsentedTokenColumnEnabled()) {
            boolean isConsentedToken = accessTokenDO.isConsentedToken();
            return OIDCClaimUtil.filterUserClaimsBasedOnConsent(userClaims, user, clientId, tenantDomain, grantType,
                    getServiceProvider(tenantDomain, clientId), isConsentedToken);
        }
        return OIDCClaimUtil.filterUserClaimsBasedOnConsent(userClaims, user, clientId, tenantDomain, grantType,
                getServiceProvider(tenantDomain, clientId));
    }


    protected Map<String, Object> getEssentialClaims(OAuth2TokenValidationResponseDTO tokenResponse,
                                                     Map<String, Object> claims) throws UserInfoEndpointException {

        return resolveEssentialClaims(claims, OAuth2Util.getAccessTokenIdentifier(tokenResponse), null);

    }

    protected Map<String, Object> getEssentialClaims(Map<String, Object> claims, AccessTokenDO accessTokenDO)
            throws UserInfoEndpointException {

        return resolveEssentialClaims(claims, accessTokenDO.getAccessToken(), accessTokenDO);

    }

    private Map<String, Object> resolveEssentialClaims(Map<String, Object> claims, String accessToken,
                                                       AccessTokenDO accessTokenDO)
            throws UserInfoEndpointException {

        Map<String, Object> essentialClaimMap = new HashMap<>();
        List<String> essentialClaims;
        if (accessTokenDO != null) {
            essentialClaims = getEssentialClaimUris(accessTokenDO);
        } else {
            essentialClaims = getEssentialClaimUris(accessToken);
        }
        if (isNotEmpty(essentialClaims)) {
            for (String key : essentialClaims) {
                essentialClaimMap.put(key, claims.get(key));
            }
        }
        return essentialClaimMap;
    }

    /**
     * Retrieve User claims in OIDC Dialect.
     *
     * @param tokenValidationResponse
     * @return Map of user claims, Map<"oidc_claim_uri", "claimValue">
     * @throws UserInfoEndpointException
     */
    protected abstract Map<String, Object> retrieveUserClaims(OAuth2TokenValidationResponseDTO tokenValidationResponse)
            throws UserInfoEndpointException;

    /**
     * Build UserInfo response to be sent back to the client.
     *
     * @param tokenResponse      {@link OAuth2TokenValidationResponseDTO} Token Validation response containing metadata
     *                           about the access token used for user info call.
     * @param spTenantDomain     Service Provider tenant domain.
     * @param filteredUserClaims Filtered user claims based on the requested scopes.
     * @return UserInfo Response String to be sent in the response.
     * @throws UserInfoEndpointException
     */
    protected abstract String buildResponse(OAuth2TokenValidationResponseDTO tokenResponse,
                                            String spTenantDomain,
                                            Map<String, Object> filteredUserClaims) throws UserInfoEndpointException;

    private AuthenticatedUser getAuthenticatedUser(String accessToken) throws OAuthSystemException {

        AccessTokenDO accessTokenDO;
        try {
            accessTokenDO = OAuth2Util.getAccessTokenDOfromTokenIdentifier(accessToken);
            return OAuth2Util.getAuthenticatedUser(accessTokenDO);
        } catch (IdentityOAuth2Exception e) {
            throw new OAuthSystemException();
        }
    }

    private String getServiceProviderTenantDomain(String clientId) throws UserInfoEndpointException {

        OAuthAppDO oAuthAppDO;
        try {
            oAuthAppDO = OAuth2Util.getAppInformationByClientId(clientId);
        } catch (IdentityOAuth2Exception | InvalidOAuthClientException e) {
            throw new UserInfoEndpointException(
                    "Error while retrieving OAuth app information for clientId: " + clientId);
        }
        return OAuth2Util.getTenantDomainOfOauthApp(oAuthAppDO);
    }

    private ServiceProvider getServiceProvider(String tenantDomain, String clientId) throws UserInfoEndpointException {

        ApplicationManagementService applicationMgtService = OAuth2ServiceComponentHolder.getApplicationMgtService();
        ServiceProvider serviceProvider;
        try {
            // Get the Service Provider.
            serviceProvider = applicationMgtService.getServiceProviderByClientId(
                    clientId, IdentityApplicationConstants.OAuth2.NAME, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new UserInfoEndpointException("Error while obtaining the service provider for client_id: " +
                    clientId + " of tenantDomain: " + tenantDomain, e);
        }
        return serviceProvider;
    }

    private List<String> getEssentialClaimUris(String accessToken) throws UserInfoEndpointException {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken);
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByToken(cacheKey);

        if (cacheEntry != null) {
            if (isNotEmpty(cacheEntry.getEssentialClaims())) {
                return OAuth2Util.getEssentialClaims(cacheEntry.getEssentialClaims(), USERINFO);
            }
        }
        return new ArrayList<>();
    }

    private List<String> getEssentialClaimUris(AccessTokenDO accessToken) throws UserInfoEndpointException {

        AuthorizationGrantCacheKey cacheKey = new AuthorizationGrantCacheKey(accessToken.getAccessToken());
        AuthorizationGrantCacheEntry cacheEntry = AuthorizationGrantCache.getInstance()
                .getValueFromCacheByTokenId(cacheKey, accessToken.getTokenId());

        if (cacheEntry != null) {
            if (isNotEmpty(cacheEntry.getEssentialClaims())) {
                return OAuth2Util.getEssentialClaims(cacheEntry.getEssentialClaims(), USERINFO);
            }
        }
        return new ArrayList<>();
    }
}
