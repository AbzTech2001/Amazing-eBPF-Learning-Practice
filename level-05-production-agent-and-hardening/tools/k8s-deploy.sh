#!/bin/bash
# Deploy eBPF agent to Kubernetes

set -e

# Configuration
NAMESPACE=${NAMESPACE:-"ebpf-system"}
AGENT_NAME=${AGENT_NAME:-"ebpf-agent"}
IMAGE=${IMAGE:-"ebpf-agent:latest"}

echo "========================================="
echo "Kubernetes eBPF Agent Deployment"
echo "========================================="
echo ""

usage() {
    echo "Usage: $0 <deploy|delete|status>"
    echo ""
    echo "Commands:"
    echo "  deploy  - Deploy agent as DaemonSet"
    echo "  delete  - Remove agent"
    echo "  status  - Check deployment status"
    echo ""
    echo "Environment variables:"
    echo "  NAMESPACE   - Kubernetes namespace (default: ebpf-system)"
    echo "  AGENT_NAME  - Agent name (default: ebpf-agent)"
    echo "  IMAGE       - Container image (default: ebpf-agent:latest)"
    exit 1
}

check_kubectl() {
    if ! command -v kubectl &> /dev/null; then
        echo "Error: kubectl not found"
        exit 1
    fi

    if ! kubectl cluster-info &> /dev/null; then
        echo "Error: Cannot connect to Kubernetes cluster"
        exit 1
    fi
}

deploy_agent() {
    echo "Deploying $AGENT_NAME to namespace $NAMESPACE..."
    echo ""

    # Create namespace
    echo "Creating namespace..."
    kubectl create namespace $NAMESPACE --dry-run=client -o yaml | kubectl apply -f -

    # Create service account
    echo "Creating service account..."
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: $AGENT_NAME
  namespace: $NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: $AGENT_NAME
rules:
  - apiGroups: [""]
    resources: ["nodes", "pods"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: $AGENT_NAME
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: $AGENT_NAME
subjects:
  - kind: ServiceAccount
    name: $AGENT_NAME
    namespace: $NAMESPACE
EOF

    # Deploy DaemonSet
    echo "Creating DaemonSet..."
    cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: $AGENT_NAME
  namespace: $NAMESPACE
  labels:
    app: $AGENT_NAME
spec:
  selector:
    matchLabels:
      app: $AGENT_NAME
  template:
    metadata:
      labels:
        app: $AGENT_NAME
    spec:
      serviceAccountName: $AGENT_NAME
      hostPID: true
      hostNetwork: true
      containers:
      - name: $AGENT_NAME
        image: $IMAGE
        imagePullPolicy: IfNotPresent
        securityContext:
          privileged: true  # Required for BPF
          capabilities:
            add:
              - SYS_ADMIN    # For BPF operations
              - SYS_RESOURCE # For resource limits
              - NET_ADMIN    # For network programs
        volumeMounts:
        - name: sys
          mountPath: /sys
          readOnly: true
        - name: debugfs
          mountPath: /sys/kernel/debug
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "100m"
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
      volumes:
      - name: sys
        hostPath:
          path: /sys
      - name: debugfs
        hostPath:
          path: /sys/kernel/debug
      tolerations:
      - effect: NoSchedule
        operator: Exists
      - effect: NoExecute
        operator: Exists
EOF

    # Create Service for metrics
    echo "Creating Service..."
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Service
metadata:
  name: $AGENT_NAME-metrics
  namespace: $NAMESPACE
  labels:
    app: $AGENT_NAME
spec:
  type: ClusterIP
  ports:
  - name: metrics
    port: 9090
    targetPort: 9090
    protocol: TCP
  selector:
    app: $AGENT_NAME
EOF

    echo ""
    echo "✓ Deployment complete!"
    echo ""
    echo "Check status with:"
    echo "  kubectl get daemonset -n $NAMESPACE"
    echo "  kubectl get pods -n $NAMESPACE"
    echo ""
    echo "View logs:"
    echo "  kubectl logs -n $NAMESPACE -l app=$AGENT_NAME -f"
    echo ""
    echo "Access metrics:"
    echo "  kubectl port-forward -n $NAMESPACE svc/$AGENT_NAME-metrics 9090:9090"
}

delete_agent() {
    echo "Deleting $AGENT_NAME from namespace $NAMESPACE..."
    echo ""

    kubectl delete daemonset $AGENT_NAME -n $NAMESPACE --ignore-not-found=true
    kubectl delete service $AGENT_NAME-metrics -n $NAMESPACE --ignore-not-found=true
    kubectl delete clusterrolebinding $AGENT_NAME --ignore-not-found=true
    kubectl delete clusterrole $AGENT_NAME --ignore-not-found=true
    kubectl delete serviceaccount $AGENT_NAME -n $NAMESPACE --ignore-not-found=true

    echo ""
    read -p "Delete namespace $NAMESPACE? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        kubectl delete namespace $NAMESPACE --ignore-not-found=true
        echo "✓ Namespace deleted"
    fi

    echo ""
    echo "✓ Agent deleted"
}

show_status() {
    echo "Status for $AGENT_NAME in namespace $NAMESPACE:"
    echo ""

    if ! kubectl get namespace $NAMESPACE &> /dev/null; then
        echo "✗ Namespace $NAMESPACE does not exist"
        return 1
    fi

    echo "=== DaemonSet ==="
    kubectl get daemonset $AGENT_NAME -n $NAMESPACE 2>/dev/null || echo "Not found"
    echo ""

    echo "=== Pods ==="
    kubectl get pods -n $NAMESPACE -l app=$AGENT_NAME 2>/dev/null || echo "Not found"
    echo ""

    echo "=== Service ==="
    kubectl get service $AGENT_NAME-metrics -n $NAMESPACE 2>/dev/null || echo "Not found"
    echo ""

    echo "=== Recent Events ==="
    kubectl get events -n $NAMESPACE --sort-by='.lastTimestamp' 2>/dev/null | tail -10
}

# Main
check_kubectl

case "$1" in
    deploy)
        deploy_agent
        ;;
    delete)
        delete_agent
        ;;
    status)
        show_status
        ;;
    *)
        usage
        ;;
esac
