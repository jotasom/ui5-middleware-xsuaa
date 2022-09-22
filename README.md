# ui5-middleware-xsuaa

This is a middleware that supports XSUAA authentication to SAP BTP - Cloud Foundry services using either of the following grant types:
- Authorization Code
- Client Credentials

## Sample Configuration

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

- Add optional backend.redirectUri, so that the middleware can set up an endpoint for the XSUAA service to redirect to
- Add support for destination service
