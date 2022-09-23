# oidc-auth
OIDC authentication for NGINX auth_request.

Inspired by [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy). Unlike oauth2-proxy it doesn't support proxy mode. It's mainly intended to work with NGINX auth_request module.

## Environment Variables
| Name | Description |
| ---- | ----------- |
| ISSUER | The OpenID issuer URL |
| INSECURE_SKIP_VERIFY | Disable TLS certificate validation when connecting to the OpenID connect provider |
| SCOPES | The OpenID connect scopes |
| CLIENT_ID | The client id |
| CLIENT_SECRET | The client secret |
| PORT | The port the server will listen on |

## State machine
![state machine](oidc-auth.png "State machine")

## Endpoints
- /auth/login
- /auth/logout
- /auth/callback
- /auth/decisions[?allowed_groups=...&allowed_emails=...]

## ingress-nginx
The Ingress for the service you are trying to secure:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  namespace: http-bin
  name: http-bin
  annotations:
    nginx.ingress.kubernetes.io/auth-response-headers: Authorization,X-Auth-Request-User,X-Auth-Request-Subject,X-Auth-Request-Preferred-Username,X-Auth-Request-Groups,X-Auth-Request-Email
    nginx.ingress.kubernetes.io/auth-url: "https://$host/auth/decisions"
    nginx.ingress.kubernetes.io/auth-signin: "https://$host/auth/login"
    nginx.ingress.kubernetes.io/auth-always-set-cookie: "true"
spec:
  ingressClassName: nginx
  tls:
    - hosts: ["http-bin.test"]
  rules:
  - host: oauth-bin.test
    http:
      paths:
      - pathType: Prefix
        path: "/"
        backend:
          service:
            name: http-bin
            port:
              name:  http
```
A corresponding Ingress for the `/auth` URL in the same namespace `oidc-auth` is deployed in:
```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  namespace: oidc-auth
  name: http-bin-auth
spec:
  ingressClassName: nginx
  tls:
    - hosts: ["http-bin.test"]
  rules:
    - host: http-bin.test
      http:
        paths:
          - pathType: Prefix
            path: /auth
            backend:
              service:
                name: oidc-auth
                port:
                  number: 80
```

## Deploy
Use `kustomize` to create the Deployment and Service. You will have to create the Secret `oidc-auth` with all the environment variables.
