/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.carbon.identity.oauth.listener;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.bean.context.MessageContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.bean.IdentityEventMessageContext;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.handler.AbstractEventHandler;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.Map;

/**
 * Revokes the outstanding OAuth2 tokens and authorization codes of an agent as soon as the agent enrols a passkey.
 * <p>
 * An agent is first provisioned with a one-time setup secret which it exchanges for a token in order to register a
 * passkey. Once the passkey is enrolled the setup secret is no longer needed, so any token minted with it must be
 * revoked. This handler removes the manual revocation step by reacting to the
 * {@code POST_FINISH_FIDO2_REGISTRATION} event fired by the FIDO2 component after a successful registration.
 * <p>
 * Only identities that belong to the agent userstore are affected; passkey enrolments by regular (human) users are
 * ignored so their sessions/tokens are left intact.
 */
public class AgentPasskeyEnrolmentTokenRevocationHandler extends AbstractEventHandler {

    private static final Log log = LogFactory.getLog(AgentPasskeyEnrolmentTokenRevocationHandler.class);

    // Must match the event name fired by the FIDO2 component (WebAuthnService#fireFinishRegistrationEvent).
    private static final String POST_FINISH_FIDO2_REGISTRATION_EVENT = "POST_FINISH_FIDO2_REGISTRATION";

    @Override
    public boolean canHandle(MessageContext messageContext) {

        Event event = ((IdentityEventMessageContext) messageContext).getEvent();
        return POST_FINISH_FIDO2_REGISTRATION_EVENT.equals(event.getEventName());
    }

    /**
     * This handler self-subscribes to the event via {@link #canHandle} rather than through an
     * {@code identity-event.properties} module entry, so no subscription-backed {@code ModuleConfiguration} is
     * initialised for it. The revocation is executed synchronously (in the same thread as the registration) so
     * the outstanding tokens are already gone by the time the enrolment call returns; hence this always returns
     * {@code false} and never consults the (absent) subscription properties.
     */
    @Override
    public boolean isAssociationAsync(String eventName) {

        return false;
    }

    @Override
    public void handleEvent(Event event) throws IdentityEventException {

        if (!POST_FINISH_FIDO2_REGISTRATION_EVENT.equals(event.getEventName())) {
            return;
        }

        Map<String, Object> eventProperties = event.getEventProperties();
        String username = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_NAME);
        String userStoreDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN);
        String tenantDomain = (String) eventProperties.get(IdentityEventConstants.EventProperty.TENANT_DOMAIN);

        if (StringUtils.isBlank(username) || StringUtils.isBlank(tenantDomain)) {
            log.warn("Username or tenant domain is missing in the " + POST_FINISH_FIDO2_REGISTRATION_EVENT
                    + " event. Skipping agent token revocation.");
            return;
        }

        // Only revoke tokens for agent identities; human passkey enrolments are left untouched.
        if (!isAgentUserStore(userStoreDomain)) {
            if (log.isDebugEnabled()) {
                log.debug("Passkey was enrolled for a non-agent identity in userstore domain: " + userStoreDomain
                        + ". Skipping token revocation.");
            }
            return;
        }

        try {
            UserStoreManager userStoreManager = getAgentUserStoreManager(tenantDomain, userStoreDomain);
            if (userStoreManager == null) {
                log.warn("Could not resolve the userstore manager for domain: " + userStoreDomain + " in tenant: "
                        + tenantDomain + ". Skipping agent token revocation.");
                return;
            }

            boolean tokensRevoked = OAuthUtil.revokeTokens(username, userStoreManager);
            boolean authzCodesRevoked = OAuthUtil.revokeAuthzCodes(username, userStoreManager);

            if (log.isDebugEnabled()) {
                log.debug("Agent passkey enrolment token revocation for user: " + username + " in userstore: "
                        + userStoreDomain + " - tokens revoked: " + tokensRevoked + ", authorization codes revoked: "
                        + authzCodesRevoked);
            }
        } catch (UserStoreException e) {
            throw new IdentityEventException("Error while revoking tokens of the agent: " + username
                    + " after passkey enrolment.", e);
        }
    }

    @Override
    public String getName() {

        return "agentPasskeyEnrolmentTokenRevocationHandler";
    }

    private boolean  isAgentUserStore(String userStoreDomain) {

        return StringUtils.isNotBlank(userStoreDomain)
                && userStoreDomain.equalsIgnoreCase(IdentityUtil.getAgentIdentityUserstoreName());
    }

    /**
     * Resolve the userstore manager that owns the agent identity so that its tokens can be revoked.
     *
     * @param tenantDomain    Tenant domain of the agent.
     * @param userStoreDomain Userstore domain of the agent (the agent userstore).
     * @return the agent userstore manager, or {@code null} if it cannot be resolved.
     * @throws UserStoreException if resolving the realm fails.
     */
    private UserStoreManager getAgentUserStoreManager(String tenantDomain, String userStoreDomain)
            throws UserStoreException {

        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        if (realmService == null) {
            return null;
        }
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        UserStoreManager userStoreManager =
                (UserStoreManager) realmService.getTenantUserRealm(tenantId).getUserStoreManager();
        if (userStoreManager == null) {
            return null;
        }
        // The agent userstore is a secondary userstore; resolve it unless it happens to be the primary domain.
        if (!StringUtils.equalsIgnoreCase(userStoreDomain, UserCoreUtil.getDomainName(
                userStoreManager.getRealmConfiguration()))) {
            userStoreManager = (UserStoreManager) userStoreManager.getSecondaryUserStoreManager(userStoreDomain);
        }
        return userStoreManager;
    }
}
