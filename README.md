[![NPM Version](http://img.shields.io/npm/v/ui5-middleware-xsuaa.svg?style=flat-square)](https://npmjs.com/package/ui5-middleware-xsuaa)
[![License](http://img.shields.io/npm/l/ui5-middleware-xsuaa.svg?style=flat-square)](http://opensource.org/licenses/MIT)
![Build](https://github.com/jotasom/ui5-middleware-xsuaa/actions/workflows/npm-publish.yml/badge.svg)

# ui5-middleware-xsuaa

This is a middleware that supports XSUAA authentication to SAP BTP - Cloud Foundry services using either of the following grant types:
- Authorization Code
- Client Credentials

## Sample Configuration

First, install this library using npm. Also, add `ui5-middleware-xsuaa` to `ui5.dependencies` on the `package.json` file.

Put the following under `customMiddleware` in `ui5.yaml`:

```yaml
    - name: ui5-middleware-xsuaa
      afterMiddleware: compression
      configuration:
        authorizationCodePath: /xsuaa
        backend:
          - path: /bpmworkflowruntime
            pathPrefix: /
            service: com.sap.bpm.workflow
            endpoint: workflow_rest_url
          - path: /bpmworkflowodata
            pathPrefix: /
            service: com.sap.bpm.workflow
            endpoint: workflow_odata_url
            grantType: authorizationCode
```

Make sure all needed services are properly bound on a `.env` file located in the same folder as the `ui5.yaml` file¹.

¹ On SAP Business Application Studio, go to `View` > `Find Command...` > `CF: Bind a service to a locally run application`.

## TODO

- Once an authorization has expired, set each backend to "not authorized" and re-authenticate them (if possible)
- Add optional backend.redirectUri, so that the middleware can set up an endpoint for the XSUAA service to redirect to
- Add support for destination service
