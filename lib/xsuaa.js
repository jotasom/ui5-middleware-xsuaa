const log = require("@ui5/logger").getLogger("server:custommiddleware:xsuaa");
const https = require("https");
const fs = require("fs");
const dirname = __dirname;
require("dotenv").config();

const oauth2 = require("oauth2.js");

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

        if (backend.destination) {
            if (!options.destinationSrv) {
                options.destinationSrv = new oauth2.DestinationServiceInstance();
                options.destinationSrv.authorize().catch(log.error);
            }

            backend._srv = new oauth2.Destination({
                service: options.destinationSrv,
                name: backend.destination
            });

            backend._srv.authorize().catch(log.error);
            return;
        }

        if (!backend.service || !backend.path) {
            log.error(`Misconfigured backend: ${ JSON.stringify(backend) }`);
            return;
        }

        backend._srv = new oauth2.ServiceInstance(backend);

        if (backend.grantType === "authorizationCode") {
            backend._manual = true;
        } else {
            backend._srv.authorize().catch(log.error);
        }
    });
    
	return (req, res, next) => {
		const reqPath = middlewareUtil.getPathname(req);
        const backend = options.backend.find(backend => {
            return reqPath.startsWith(backend.path);
        });

        if (backend) {
            const endpoint = backend._srv.getEndpoint(backend.endpoint);

            if (endpoint) {
                const suffixMatch = req.originalUrl.match(/\?.+/);
                const pathPrefix = backend.pathPrefix || backend.path;
                const targetPath = reqPath.replace(backend.path, pathPrefix).substring(1);
                const url = endpoint + targetPath + (suffixMatch ? suffixMatch[0] : "");

                log.info(`Proxying ${ req.method } ${ req.originalUrl } to ${ url }`);

                const objUrl = new URL(url);

                const headersCopy = Object.assign({}, req.headers);
                delete headersCopy.host;

                try {
                    headersCopy["Authorization"] = backend.getAuthentication();
                } catch (error) {
                    log.error(error.toString());
                    res.statusCode = 500;
                    res.end(error.toString());
                }

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
                backend.authorizationCode = req.query.code;

                backend._srv.authorize().then(() => {
                    res.end();
                }).catch(error => {
                    log.error(error);
                    res.statusCode = 500;
                    res.end(error);
                });

            } else if (req.query.fetch) {
                const backends = options.backend;
                const json = backends.map((backend, index) => {
                    const uaa = backend._srv.config.credentials.uaa;

                    return {
                        code: "",
                        name: backend.path,
                        manual: backend._manual,
                        status: backend.state,
                        error: backend.error ? backend.error.toString() : null,
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