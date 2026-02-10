# Kubernetes Security Patterns

Secure configuration patterns for Kubernetes resources.

## Pod Security

### Secure Pod Spec

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  # Pod-level security context
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault

  # Service account with minimal permissions
  serviceAccountName: app-service-account
  automountServiceAccountToken: false  # Disable if not needed

  containers:
  - name: app
    image: myapp:1.0.0@sha256:abc123...  # Pin digest
    
    # Container-level security context
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
        # Only add specific capabilities if needed
        # add:
        #   - NET_BIND_SERVICE
    
    # Resource limits (prevent DoS)
    resources:
      limits:
        cpu: "500m"
        memory: "512Mi"
      requests:
        cpu: "200m"
        memory: "256Mi"
    
    # Health checks
    livenessProbe:
      httpGet:
        path: /healthz
        port: 8080
      initialDelaySeconds: 10
      periodSeconds: 10
    
    readinessProbe:
      httpGet:
        path: /ready
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
    
    # Volume mounts (read-only where possible)
    volumeMounts:
    - name: config
      mountPath: /etc/app
      readOnly: true
    - name: tmp
      mountPath: /tmp

  volumes:
  - name: config
    configMap:
      name: app-config
  - name: tmp
    emptyDir: {}
```

### Secure Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      
      # Use dedicated service account
      serviceAccountName: myapp-sa
      automountServiceAccountToken: false
      
      containers:
      - name: app
        image: myapp:1.0.0@sha256:abc123...
        ports:
        - containerPort: 8080
          protocol: TCP
        
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL
        
        resources:
          limits:
            cpu: "500m"
            memory: "512Mi"
          requests:
            cpu: "200m"
            memory: "256Mi"
        
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password
        
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      
      volumes:
      - name: tmp
        emptyDir: {}
```

---

## Network Security

### Network Policy (Default Deny)

```yaml
# Default deny all ingress and egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}  # Applies to all pods
  policyTypes:
  - Ingress
  - Egress
```

### Network Policy (Allow Specific)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-app-traffic
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Ingress
  - Egress
  
  ingress:
  # Allow from specific namespace
  - from:
    - namespaceSelector:
        matchLabels:
          name: frontend
    - podSelector:
        matchLabels:
          app: web
    ports:
    - protocol: TCP
      port: 8080
  
  egress:
  # Allow to database
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  # Allow DNS
  - to:
    - namespaceSelector: {}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
```

---

## RBAC Security

### Service Account (Minimal)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-sa
  namespace: production
automountServiceAccountToken: false
```

### Role (Least Privilege)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: myapp-role
  namespace: production
rules:
# Only specific resources
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["myapp-config"]  # Specific resource
  verbs: ["get"]

# Read secrets (specific)
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["myapp-secrets"]
  verbs: ["get"]
```

### Role Binding

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: myapp-rolebinding
  namespace: production
subjects:
- kind: ServiceAccount
  name: myapp-sa
  namespace: production
roleRef:
  kind: Role
  name: myapp-role
  apiGroup: rbac.authorization.k8s.io
```

---

## Secrets Management

### External Secrets (Preferred)

```yaml
# Use external-secrets-operator
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: db-credentials
  data:
  - secretKey: password
    remoteRef:
      key: production/db/password
```

### Sealed Secrets (Alternative)

```yaml
# Encrypted secret (safe to commit)
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: db-credentials
spec:
  encryptedData:
    password: AgB...encrypted...data
```

---

## Pod Security Standards

### Restricted Policy

```yaml
apiVersion: pod-security.kubernetes.io/v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

---

## Anti-Patterns to Avoid

### Never Do This

```yaml
# ❌ Running as root
spec:
  containers:
  - name: app
    securityContext:
      runAsUser: 0  # Root!

# ❌ Privileged container
spec:
  containers:
  - name: app
    securityContext:
      privileged: true  # Full host access!

# ❌ Mounting host paths
spec:
  volumes:
  - name: host
    hostPath:
      path: /  # Entire host filesystem!

# ❌ Using latest tag
spec:
  containers:
  - name: app
    image: myapp:latest  # Unpredictable!

# ❌ No resource limits
spec:
  containers:
  - name: app
    # Missing resources block = can DoS node

# ❌ Hardcoded secrets
spec:
  containers:
  - name: app
    env:
    - name: PASSWORD
      value: "SuperSecret123"  # In plain text!

# ❌ Wildcard RBAC
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]  # Admin access to everything!
```

---

## Image Security

### Secure Image References

```yaml
# ✅ Good - pinned digest
image: myapp@sha256:abc123def456...

# ✅ Good - specific version
image: myapp:1.2.3

# ❌ Bad - floating tag
image: myapp:latest
image: myapp
```

### Image Pull Policy

```yaml
spec:
  containers:
  - name: app
    image: myapp:1.2.3@sha256:abc123...
    imagePullPolicy: Always  # Verify each time
```

---

## Checklist

Before deploying any Kubernetes resource:

- [ ] Runs as non-root user
- [ ] Read-only root filesystem
- [ ] All capabilities dropped
- [ ] Resource limits set
- [ ] Image pinned with digest
- [ ] Network policy applied
- [ ] Service account with minimal RBAC
- [ ] Secrets from external source
- [ ] Pod security standards enforced
- [ ] Health probes configured
