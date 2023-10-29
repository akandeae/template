const https = require('https');
const xml2js = require('xml2js');
const AWS = require('aws-sdk');

const REQUIRED_FIELDS = [
    'firstName', 'lastName', 'email', 'phone', 'country',
    'state', 'city', 'zip', 'liquidAssetRange', 'netWorth', 'ownershipType'
];
const MAX_RETRIES = 1;
const EMAIL_REGEX = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
const MIN_PHONE_LENGTH = 10;
const DEFAULT_LEAD_MODULE = 'fs';
const DEFAULT_LEAD_SUBMODULE = 'lead';
const DEFAULT_LEAD_RESPONSE_TYPE = 'JSON';
const CORS_HEADERS = {
    "Access-Control-Allow-Headers": "application/json",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "OPTIONS,POST"
};
const ERROR_MESSAGES = {
    GENERIC_ERROR: "Something went wrong",
    INVALID_EMAIL: "Invalid email format",
    INVALID_PHONE: "Invalid phone number"
};
const SUCCESS_MESSAGES = {
    LEAD_CREATED: "Successfully submitted"
};

const secretsManager = new AWS.SecretsManager();

exports.handler = async (event) => {
    try {
        const secrets = await getSecrets();
        console.log("Successfully retrieved secrets");
        const requestBody = JSON.parse(event.body);
        const validationError = validateRequestBody(requestBody);
        if (validationError) {
            console.warn("Request body validation failed:", validationError);
            return errorResponse(400, validationError);
        }
        let tokenData = await getAccessToken(secrets);
        console.log("Access token obtained");
        let accessToken = tokenData.access_token;
        const createResponse = await createLead(accessToken, requestBody, secrets);
        if (createResponse.success) {
            return baseResponse(200, true, SUCCESS_MESSAGES.LEAD_CREATED, createResponse.referenceId);
        } else {
            return errorResponse(400, ERROR_MESSAGES.GENERIC_ERROR);
        }
    } catch (error) {
        console.error("Error occurred:", error);
        return errorResponse(500, ERROR_MESSAGES.GENERIC_ERROR);
    }
};


const getSecrets = async () => {
    const secretId = process.env.SECRET_ID;
    const data = await secretsManager.getSecretValue({ SecretId: secretId }).promise();
    return JSON.parse(data.SecretString);
};


const validateRequestBody = (body) => {
    for (const field of REQUIRED_FIELDS) {
        if (!body[field]) {
            return `Missing required field: ${field}`;
        }
    }
    // Email validation
    if (!EMAIL_REGEX.test(body.email)) {
        return ERROR_MESSAGES.INVALID_EMAIL;
    }
    // Phone validation
    if (body.phone.length < MIN_PHONE_LENGTH) {
        return ERROR_MESSAGES.INVALID_PHONE;
    }
    return null;
};

const makeHttpRequest = (options) => {
    return new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                resolve(JSON.parse(data));
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        req.end();
    });
};


const getAccessToken = async (secrets) => {
    const clientId = secrets.CLIENT_ID;
    const clientSecret = secrets.CLIENT_SECRET;
    const hostname = secrets.AUTH_HOSTNAME;
    const tenantID = secrets.TENANT_ID;
    const grantType = secrets.GRANT_TYPE;

    const credentials = `${clientId}:${clientSecret}`;
    const base64Credentials = Buffer.from(credentials).toString('base64');

    const options = {
        hostname: hostname,
        path: `/userauth/oauth/token?X-TenantID=${tenantID}&grant_type=${grantType}`,
        method: 'POST',
        headers: {
            'Authorization': `Basic ${base64Credentials}`,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    };

    const data = await makeHttpRequest(options);
    if (data.access_token && data.expires_in) {
        return {
            access_token: data.access_token,
            expires_in: data.expires_in
        };
    } else {
        console.error("Failed to obtain access token or expiration time");
        throw new Error("Failed to obtain access token or expiration time");
    }
};

const createLead = async (accessToken, leadData, secrets) => {
    let retries = 0;

    while (retries <= MAX_RETRIES) {
        try {
            const response = await makeCreateLeadRequest(accessToken, leadData, secrets);
            return response;
        } catch (error) {
            if (error.message === 'Invalid:access_token' && retries < maxRetries) {
                console.warn("Invalid access token, regenerating...");
                const tokenData = await getAccessToken(secrets);
                console.log("New access token generated");
                accessToken = tokenData.access_token;
                retries++;
            } else {
                console.error("Error while creating lead:", error);
                throw error;
            }
        }
    }
    console.error("Failed to create lead after retries");
    throw new Error("Failed to create lead after retries");
};

const makeCreateLeadRequest = async (accessToken, leadData, secrets) => {
    const xmlString = encodeURIComponent(generateXmlString(leadData));
    const hostname = secrets.LEAD_HOSTNAME;
    const module = secrets.LEAD_MODULE || DEFAULT_LEAD_MODULE;
    const subModule = secrets.LEAD_SUBMODULE || DEFAULT_LEAD_SUBMODULE;
    const responseType = secrets.LEAD_RESPONSE_TYPE || DEFAULT_LEAD_RESPONSE_TYPE;

    const options = {
        hostname: hostname,
        path: `/fc/rest/dataservices/create?module=${module}&subModule=${subModule}&responseType=${responseType}&xmlString=${xmlString}`,
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${accessToken}`,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    };

    const data = await makeHttpRequest(options);
    if (data.fcResponse.responseStatus === "Error" && data.fcResponse.error.errorDetails === "Invalid:access_token") {
        throw new Error('Invalid:access_token');
    } else if (data.fcResponse.responseStatus === "Success") {
        return {
            success: true,
            message: SUCCESS_MESSAGES.LEAD_CREATED,
            referenceId: data.fcResponse.responseData.fsLead.referenceId
        };
    } else if (data.fcResponse.responseStatus === "Warning") {
        return {
            success: true,
            message: `Successfully submitted with a warning: ${data.fcResponse.responseData.fsLead.warning.warningDetails}`,
            referenceId: data.fcResponse.responseData.fsLead.referenceId
        };
    } else {
        throw new Error(ERROR_MESSAGES.GENERIC_ERROR);
    }
};

const generateXmlString = (leadData) => {
    const builder = new xml2js.Builder();
    const xmlObj = {
        fcRequest: {
            fsLead: {
                firstName: leadData.firstName,
                lastName: leadData.lastName,
                emailID: leadData.email,
                mobile: leadData.phone,
                country: leadData.country,
                stateID: leadData.state,
                city: leadData.city,
                zip: leadData.zip,
                _netWorthRange1193748353: leadData.netWorth,
                leadSource2ID: 'Internet',
                leadSource3ID: 'zaxbysfranchising.com',
                liquidCapitalMax: leadData.liquidAssetRange,
                _typeOfOwnershipYouIdentifyWith11994576: leadData.ownershipType
            }
        }
    };
    return builder.buildObject(xmlObj);
};

const baseResponse = (statusCode, success, message, referenceId = null) => {
    const responseBody = {
        success: success,
        message: message
    };
    if (referenceId) {
        responseBody.referenceId = referenceId;
    }
    return {
        statusCode: statusCode,
        headers: CORS_HEADERS,
        body: JSON.stringify(responseBody)
    };
};


// Error response function
const errorResponse = (statusCode, message) => {
    return baseResponse(statusCode, false, message);
};

