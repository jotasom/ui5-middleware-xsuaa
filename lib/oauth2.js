function findBoundService(filterFn) {
    let services = process.env.VCAP_SERVICES;
    if (!services) {
        log.error(`.env file could not be read.`);
        services = [];
    }

    const json = JSON.parse(services);
    const values = Object.values(json);
    const list = values.flat();

    const service = list.find(filterFn);

    if (!service) {
        log.error(`Service ${ serviceName } is not bound.`);
    }

    return service;
}

module.exports = {
    ServiceInstance,
    DestinationServiceInstance,
    Destination
};

class OAuth2Service {

    clientid = null;
    clientsecret = null;
    uaaurl = null;

    authorizationCode = null;
    accessToken = null;
    grantType = null;

    authorizationError = null;
    authorizationPending = false;

    constructor({ grantType, clientid, clientsecret, url }) {
        this.grantType = grantType;
        this.clientid = clientid;
        this.clientsecret = clientsecret;
        this.uaaurl = url;
    }

    get state() {
        if (this.authorizationError) {
            return "error";
        } else if (this.accessToken) {
            return "success";
        } else if (this.authorizationPending) {
            return "info";
        } else {
            return "warning";
        }
    }

    get error() {
        return this.authorizationError;
    }

    async authorize() {
        if (!this.clientid || !this.clientsecret || !this.uaaurl) {
            throw Error("No OAuth2 credentials registered.");
        }

        this.authorizationPending = true;

        try {
            let path;

            switch (this.grantType) {
                case "authorizationCode":
                    if (!this.code) {
                        throw Error("No authorization code available.");
                    }
    
                    path = `/oauth/token?grant_type=authorization_code&code=${ this.authorizationCode }`;
                    break;
                case "clientCredentials":
                    path = "/oauth/token?grant_type=client_credentials";
                    break;
                default:
                    throw Error("No valid grant type selected.");
            }
            
            const basicAuth = this.clientid + ":" + this.clientsecret;
            const basic64 = Buffer.from(basicAuth).toString("base64");
            const data = [];
            
            return new Promise ((resolve, reject) => {
                const request = https.request({
                    "method": "POST",
                    "host": this.uaaurl.replace("https://", ""),
                    "path": path,
                    "headers": {
                        "Authorization": `Basic ${ basic64 }`
                    }
                }, response => {
                    response.on("data", chunk => data.push(chunk));
                    response.on("end", () => {
                        const buffer = Buffer.concat(data);
    
                        if (response.statusCode !== 200) {
                            this.accessToken = null;
                            this.authorizationError = `Authorization failure: HTTP ${ response.statusCode }\n${ buffer.toString() }`;
                            reject();
                        } else {
                            const json = JSON.parse(buffer.toString());
                            this.accessToken = json.access_token;
                            this.authorizationError = null;
                            resolve();
                        }
                    });
                });
    
                request.on("error", reject);
                request.end();
            });
        } catch (error) {
            this.authorizationError = error;
            throw error;
        } finally {
            this.authorizationPending = false;
        }
    }

    getAuthentication() {
        if (this.authorizationError) {
            throw this.authorizationError;
        }

        if (!this.accessToken) {
            throw new Error("Access token has not yet been fetched.");
        }

        return `Bearer ${ this.accessToken }`;
    }
}

class ServiceInstance extends OAuth2Service {

    config = null;

    constructor(backend) {
        this.config = findBoundService(service => {
            if (!service.credentials) {
                return null;
            }
            
            return service.credentials["sap.cloud.service"] === backend.service;
        });

        super({
            grantType: backend.grantType,
            clientid: config.credentials.clientid,
            clientsecret: config.credentials.clientsecret,
            url: config.credentials.uaa
        });
    }

    getEndpoint(endpoint) {
        const endpoints = this.config?.credentials?.endpoints;
        return endpoints ? endpoints[endpoint] : endpoints;
    }
}

class DestinationServiceInstance extends ServiceInstance {

    authorizationPromise = null;

    constructor() {
        this.config = findBoundService(service => {        
            return service.label === "destination";
        });

        super({
            grantType: "clientCredentials",
            clientid: this.config.credentials.clientid,
            clientsecret: this.config.credentials.clientsecret,
            url: this.config.credentials.uaa
        });
    }

    async authorize() {
        this.authorizationPromise = super.authorize();
        return this.authorizationPromise;
    }
}

class Destination extends OAuth2Service {

    endpoint = null;
    service = null;
    name = null;

    constructor({ service, name }) {
        this.service = service;
        this.name = name;
    }

    async authorize() {
        if (this.service.authorizationPromise) {
            await this.authorizationPromise;
        }

        this.authorizationPending = true;

        const config = this.service.config;
        const accessHeader = super.getAuthentication();
        const path = `/destination-configuration/v1/destinations/${ this.name }`;

        return new Promise ((resolve, reject) => {
            const request = https.request({
                "method": "GET",
                "host": config.credentials.uri.replace("https://", ""),
                "path": path,
                "headers": {
                    "Authorization": accessHeader
                }
            }, response => {
                response.on("data", chunk => data.push(chunk));
                response.on("end", () => {
                    const buffer = Buffer.concat(data);

                    if (response.statusCode !== 200) {
                        this.authorizationError = `Destination service failure: ${ response.statusCode }\n${ buffer.toString() }`;
                        this.accessToken = null;
                        this.endpoint = null;
                        reject();
                    } else {
                        const json = JSON.parse(buffer.toString());
                        const access_token = json.authTokens.find(token => {
                            return token.type === "bearer";
                        });

                        this.endpoint = access_token.destinationConfiguration.URL;
                        this.authorizationError = null;
                        this.accessToken = access_token.value;
                        resolve();
                    }

                    this.authorizationPending = false;
                });
            });

            request.on("error", reject);
            request.end();
        });
    }

    getEndpoint() {
        return this.endpoint;
    }
}