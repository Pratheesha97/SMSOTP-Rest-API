package com.wso2.identity.oauth.grant.smsotp;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.smsotp.common.SMSOTPService;
import org.wso2.carbon.identity.smsotp.common.dto.ValidationResponseDTO;
import org.wso2.carbon.identity.smsotp.common.exception.SMSOTPException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.constants.UserCoreErrorConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import static com.wso2.identity.oauth.grant.smsotp.SMSOTPGrantConstants.*;

/**
 * New grant type for Identity Server
 */
public class SMSOTPGrantHandler extends AbstractAuthorizationGrantHandler  {

    private static Log log = LogFactory.getLog(SMSOTPGrantHandler.class);


    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)  throws IdentityOAuth2Exception {

        log.info("SMS OTP Grant handler is hit");

        boolean authStatus;

        // extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();
        
        String userId = null;
        String transactionId = null;
        String smsotp = null;

        // extract parameters
        for(RequestParameter parameter : parameters){
            if(GRANT_PARAM_USERID.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    userId = parameter.getValue()[0];
                }
            } else if (GRANT_PARAM_TRANSACTION_ID.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    transactionId = parameter.getValue()[0];
                }
            } else if (GRANT_PARAM_OTP.equals(parameter.getKey())) {
                if (parameter.getValue() != null && parameter.getValue().length > 0) {
                    smsotp = parameter.getValue()[0];
                }
            }
        }

        // Sanitize inputs.
        if (StringUtils.isBlank(transactionId) || StringUtils.isBlank(userId) || StringUtils.isBlank(smsotp)) {
            String missingParam = StringUtils.isBlank(transactionId) ? "transactionId"
                    : StringUtils.isBlank(userId) ? "userId"
                    : "smsOTP";
            throw new IdentityOAuth2Exception("Param is missing: " + missingParam);
        }

        ValidationResponseDTO validationResponse = isValidOTP(transactionId, userId, smsotp);

        //validate sms otp
        authStatus =  validationResponse.isValid();

        if(authStatus) {

            // Retrieve user by ID.
            AbstractUserStoreManager userStoreManager;
            User user;
            try {
                RealmService realmService = (RealmService) PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService(RealmService.class, null);
                userStoreManager =
                        (AbstractUserStoreManager) realmService.getTenantUserRealm(getTenantId()).getUserStoreManager();
                user = userStoreManager.getUserWithID(userId, null, UserCoreConstants.DEFAULT_PROFILE);
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                // Handle user not found.
                String errorCode = ((org.wso2.carbon.user.core.UserStoreException) e).getErrorCode();
                if (UserCoreErrorConstants.ErrorMessages.ERROR_CODE_NON_EXISTING_USER.getCode().equals(errorCode)) {
                    throw new IdentityOAuth2Exception("Invalid user Id");
                }
                throw new IdentityOAuth2Exception("User Store Manager Error", e);
            }

            AuthenticatedUser authenticatedUser = new AuthenticatedUser();
            authenticatedUser.setUserName(user.getUsername());
            authenticatedUser.setTenantDomain(user.getTenantDomain());
            authenticatedUser.setAuthenticatedSubjectIdentifier(user.getUsername());
            authenticatedUser.setUserStoreDomain(user.getUserStoreDomain());

            oAuthTokenReqMessageContext.setAuthorizedUser(authenticatedUser);
            oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());

        } else{

            responseBuilder(oAuthTokenReqMessageContext);
            throw new IdentityOAuth2Exception(validationResponse.getFailureReason().getDescription());

        }

        return true;
    }

    private ValidationResponseDTO isValidOTP(String transactionId, String userId, String smsotp) throws IdentityOAuth2Exception {

        ValidationResponseDTO validationResponseDTO;

        SMSOTPService smsotpService =
                (SMSOTPService) PrivilegedCarbonContext.getThreadLocalCarbonContext().getOSGiService(SMSOTPService.class, null);

        try {
            validationResponseDTO = smsotpService.validateSMSOTP(transactionId, userId, smsotp);
        } catch (SMSOTPException e) {
            throw new IdentityOAuth2Exception(e.getErrorCode(), e.getDescription(), e);
        }

        return validationResponseDTO;
    }

    private int getTenantId() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }

    /**
     * Build the response header in case the user authentication fails both locally and externally.
     *
     * @param oAuthTokenReqMessageContext    OAuthTokenReqMessageContext
     */
    public void responseBuilder(OAuthTokenReqMessageContext oAuthTokenReqMessageContext) {
        ResponseHeader responseHeader = new ResponseHeader();
        responseHeader.setKey("HTTP_STATUS_CODE");
        responseHeader.setValue("401");
        responseHeader.setKey("ERROR_MESSAGE");
        responseHeader.setValue("Unauthorized.");
        oAuthTokenReqMessageContext.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});
    }
    
}
