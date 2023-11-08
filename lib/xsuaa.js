const log = require("@ui5/logger").getLogger("server:custommiddleware:xsuaa");
const https = require("https");
const fs = require("fs");
const dirname = __dirname;
require("dotenv").config();

const oauth2 = require("./oauth2.js");

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
        backend: [],
        destinationSrv: null
	};

	if (userOptions.configuration) {
		Object.assign(options, userOptions.configuration);
	}

    options.backend.forEach(backend => {

        if (!backend.path) {
            log.error(`Misconfigured backend, path is missing: ${ JSON.stringify(backend) }`);
            return;
        }
        else if (backend.destination) {
            if (!options.destinationSrv) {
                try {
                    options.destinationSrv = new oauth2.DestinationServiceInstance();
                } catch (error) {
                    log.error(error);
                }
                
                options.destinationSrv.authorize().catch(log.error.bind(log));
            }

            backend._srv = new oauth2.Destination({
                service: options.destinationSrv,
                name: backend.destination
            });

            if (backend.grantType === "authorizationCode")
                backend._srv._xsuaa = new oauth2.XsUaaServiceInstance("authorizationCode"); 
        }
        else if (backend.service) {
            try {
                backend._srv = new oauth2.ServiceInstance(backend);
            } catch (error) {
                log.error(error);
            }                
        } 
        else {
            log.error(`Misconfigured backend: ${ JSON.stringify(backend) }`);
            return;
        }


        if (backend.grantType === "authorizationCode") {
            backend._manual = true;
        } else {
            backend._srv.authorize().catch(log.error.bind(log));
        }
    });
    
	return (req, res, next) => {
		const reqPath = middlewareUtil.getPathname(req);
        const backend = options.backend.find(backend => {
            return reqPath.startsWith(backend.path);
        });

        if (backend) {
            let endpoint = backend._srv.endpoint;

            if (endpoint) {
                endpoint = endpoint.replace(/\/$/, "");

                const suffixMatch = req.originalUrl.match(/\?.+/);
                const pathPrefix = backend.pathPrefix || backend.path;
                const targetPath = reqPath.replace(backend.path, pathPrefix);
                const url = endpoint + targetPath + (suffixMatch ? suffixMatch[0] : "");

                log.info(`Proxying ${ req.method } ${ req.originalUrl } to ${ url }`);

                const objUrl = new URL(url);

                const headersCopy = Object.assign({}, req.headers);
                delete headersCopy.host;

                backend._srv.getAuthentication().then(headerValue => {
                    headersCopy["Authorization"] = headerValue;

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
                }).catch(error => {
                    log.error(error);
                    res.statusCode = 500;
                    res.end(error.toString());
                });
            } else {
                const errorText = backend.destination ? `Endpoint for destination ${ backend.destination } is not present.`
                    : `Endpoint ${ backend.endpoint } for service ${ backend.service } is not present.`;
                log.error(errorText);
                res.statusCode = 500;
                res.end(errorText);
            }

            return;
        } else if (reqPath.startsWith(options.authorizationCodePath)) {
            if (req.query.id) {
                const index = Number(req.query.id);
                const backends = options.backend;
                if ( !backends[index] || !backends[index]._manual ) {
                    const errorText = `Tried to authorize an invalid backend!`;
                    log.error(errorText);
                    res.statusCode = 500;
                    res.end(errorText);
                    return;
                }

                const backend = backends[index];
                backend._srv.authorizationCode = req.query.code;

                backend._srv.authorize().then(() => {
                    res.redirect(301,reqPath);
                    res.end();
                }).catch(error => {
                    log.error(error);
                    res.statusCode = 500;
                    res.end(error.toString());
                });

            } else if (req.query.fetch) {
                const backends = options.backend;
                const json = backends.map((backend, index) => {
                    const data = {
                        code: "",
                        name: backend.path,
                        service: backend.service,
                        destination: backend.destination,
                        endpoint: backend._srv.endpoint,
                        status: backend._srv.state,
                        id: index,
                        redirectUri: false,
                    };

                    if (backend._srv.error) {
                        data.error = backend._srv.error.toString();
                    }

                    if (backend._manual) {
                        data.manual = true;

                        const uaa = backend._srv.config?.credentials?.uaa;
                        if (uaa) {
                            data.url = `${ uaa.url }/oauth/authorize?response_type=code&client_id=${ encodeURIComponent(uaa.clientid) }`;
                        } else {
                            let _xsuaa = backend._srv._xsuaa;
                            _xsuaa.redirectUri = encodeURIComponent(`${req.headers.referer}?id=${index}`);
                            data.redirectUri = true;
                            data.url = `${ _xsuaa.uaaurl }/oauth/authorize?response_type=code&client_id=${ encodeURIComponent(_xsuaa.clientid) }&redirect_uri=${ _xsuaa.redirectUri}`;
                        }
                    }

                    return data;
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