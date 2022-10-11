const log = require("@ui5/logger").getLogger("server:custommiddleware:xsuaa");
const https = require("https");
const fs = require("fs");
const dirname = __dirname;
require("dotenv").config();

function findServiceConfig(serviceName) {
    const services = process.env.VCAP_SERVICES;
    if (!services) {
        log.error(`.env file could not be read. Service ${ serviceName } cannot be used.`);
    }

    const json = JSON.parse(services);
    const values = Object.values(json);
    const list = values.flat();

    const service = list.find(service => {
        if (!service.credentials) {
            return null;
        }
        
        return service.credentials["sap.cloud.service"] === serviceName;
    });

    if (!service) {
        log.error(`Service ${ serviceName } is not bound.`);
    }

    return service;
}

function registerAuthenticator(backend) {
    let access_token;
    let error = false;

    const uaa = backend._config.credentials.uaa;
    const isAuthorizationCode = (backend.grantType === "authorizationCode");

    const authorize = async (code) => {
        const path = isAuthorizationCode ? 
            `/oauth/token?grant_type=authorization_code&code=${ code }` :
            "/oauth/token?grant_type=client_credentials";
        
        const basicAuth = uaa.clientid + ":" + uaa.clientsecret;
        const basic64 = Buffer.from(basicAuth).toString("base64");

        const data = [];
        
        return await new Promise ((resolve, reject) => {
            const request = https.request({
                "method": "POST",
                "host": uaa.url.replace("https://", ""),
                "path": path,
                "headers": {
                    "Authorization": `Basic ${ basic64 }`
                }
            }, response => {
                response.on("data", chunk => data.push(chunk));
                response.on("end", () => {
                    const buffer = Buffer.concat(data);

                    if (response.statusCode !== 200) {
                        log.error(`Authorization failure: ${ response.statusCode }\n${ buffer.toString() }`);
                        access_token = undefined;
                        error = true;
                        reject();
                    } else {
                        const json = JSON.parse(buffer.toString());
                        access_token = json.access_token;
                        error = false;
                        resolve();
                    }
                });
            });

            request.on("error", reject);
            request.end();
        });
    };

    if (isAuthorizationCode) {
        backend._authorizationCodeCallback = authorize;
    } else {
        authorize().catch(() => {});
    }

    backend._authenticactionState = () => {
        if (access_token) {
            return "success";
        } else if (error) {
            return "error";
        } else {
            return "warning";
        }
    };

    backend._authenticator = (headers) => {
        if (!access_token) {
            throw new Error("Access token has not yet been fetched.");
        }

        headers["Authorization"] = `Bearer ${ access_token }`;
    };
}

/**
 * Custom UI5 Server middleware "xsuaa"
 *
 * @param {object} parameters Parameters
 * @param {object} parameters.resources Resource collections
 * @param {module:@ui5/fs.AbstractReader} parameters.resources.all Reader or Collection to read resources of the
 *                                        root project and its dependencies
 * @param {module:@ui5/fs.AbstractReader} parameters.resources.rootProject Reader or Collection to read resources of
 *                                        the project the server is started in
 * @param {module:@ui5/fs.AbstractReader} parameters.resources.dependencies Reader or Collection to read resources of
 *                                        the projects dependencies
 * @param {object} parameters.options Options
 * @param {string} [parameters.options.configuration] Custom server middleware configuration if given in ui5.yaml
 * @param {object} parameters.middlewareUtil Specification version dependent interface to a
 *                                        [MiddlewareUtil]{@link module:@ui5/server.middleware.MiddlewareUtil} instance
 * @returns {Function} Middleware function to use
 */
module.exports = ({ resources, options: userOptions, middlewareUtil }) => {
	// provide a set of default runtime options
	const options = {
        authorizationCodePath: null,
        backend: []
	};

	if (userOptions.configuration) {
		Object.assign(options, userOptions.configuration);
	}

    options.backend.forEach(backend => {
        if (!backend.service || !backend.path) {
            log.error(`Misconfigured backend: ${ JSON.stringify(backend) }`);
            return;
        }

        backend._config = findServiceConfig(backend.service);
        registerAuthenticator(backend);
    });
    
	return (req, res, next) => {
		const reqPath = middlewareUtil.getPathname(req);
        const backend = options.backend.find(backend => {
            return reqPath.startsWith(backend.path);
        });

        if (backend) {
            const endpoints = backend._config?.credentials?.endpoints;

            if (endpoints) {
                const endpoint = endpoints[backend.endpoint];

                if (!endpoint) {
                    const errorText = `Endpoint ${ backend.endpoint } for service ${ backend.service } is not present.`;
                    log.error(errorText);
                    res.statusCode = 500;
                    res.end(errorText);
                } else {
                    const suffixMatch = req.originalUrl.match(/\?.+/);
                    const pathPrefix = backend.pathPrefix || backend.path;
                    const targetPath = reqPath.replace(backend.path, pathPrefix).substring(1);
                    const url = endpoint + targetPath + (suffixMatch ? suffixMatch[0] : "");

                    log.info(`Proxying ${ req.method } ${ req.originalUrl } to ${ url }`);

                    const objUrl = new URL(url);

                    const headersCopy = Object.assign({}, req.headers);
                    delete headersCopy.host;
                    backend._authenticator(headersCopy);

                    const proxy = https.request({
                        method: req.method,
                        headers: headersCopy,
                        host: objUrl.host,
                        path: objUrl.pathname + objUrl.search
                    }, response => {
                        res.statusCode = response.statusCode;
                        res.set(response.headers);
                        response.pipe(res, { end: true });
                    });
                
                    req.pipe(proxy, { end: true });
                }

                return;
            }
        } else if (reqPath.startsWith(options.authorizationCodePath)) {
            if (req.query.id) {
                const index = Number(req.query.id);
                const backends = options.backend;
                if (!backends[index] || !backends[index]._authorizationCodeCallback) {
                    const errorText = `Tried to authorize an invalid backend!`;
                    log.error(errorText);
                    res.statusCode = 500;
                    res.end(errorText);
                    return;
                }

                backends[index]._authorizationCodeCallback(req.query.code).then(() => {
                    res.end();
                }).catch(() => {
                    res.statusCode = 500;
                    res.end();
                });
            } else if (req.query.fetch) {
                const backends = options.backend;
                const json = backends.map((backend, index) => {
                    const uaa = backend._config.credentials.uaa;
                    return {
                        code: "",
                        name: backend.path,
                        manual: Boolean(backend._authorizationCodeCallback),
                        status: backend._authenticactionState(),
                        url: `${ uaa.url }/oauth/authorize?response_type=code&client_id=${ encodeURIComponent(uaa.clientid) }`,
                        id: index
                    };
                });
                
                res.setHeader("Content-Type", "application/json");
                res.end(JSON.stringify(json));
            } else {
                fs.promises.readFile(dirname + "/xsuaa.html").then(html => {
                    res.setHeader("Content-Type", "text/html");
                    res.end(html);
                });
            }

            return;
        }
        
        next();
	}
}
