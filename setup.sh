#!/usr/bin/env bash

set -eo pipefail

DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

function variables_from_context() {
    # Create EKS cluster without nodes
    # Generate a new kubeconfig file in the local directory
    KUBECONFIG=".kubeconfig"

    # extract details form the ecktl configuration file
    CLUSTER_NAME=${CLUSTER_NAME:=$(yq eval '.metadata.name' "${EKSCTL_CONFIG}")}

    ACCOUNT_ID=$(aws sts get-caller-identity | jq -r .Account)
    AWS_REGION=${AWS_REGION:=$(aws configure get region)}
    
    # use the default bucket?
    if [ -z "${CONTAINER_REGISTRY_BUCKET}" ]; then
        CONTAINER_REGISTRY_BUCKET="container-registry-${CLUSTER_NAME}-${ACCOUNT_ID}"
    fi

    CREATE_S3_BUCKET="false"
    if ! "aws" s3api head-bucket --bucket "${CONTAINER_REGISTRY_BUCKET}" >/dev/null 2>&1; then
        CREATE_S3_BUCKET="true"
    fi

    NAMESPACE=${NAMESPACE:='default'}

    NODE_INSTANCE_SERVICES_DESIRED_CAPACTIY=${NODE_INSTANCE_WORKSPACE_DESIRED_CAPACTIY:=1}
    NODE_INSTANCE_SERVICES_MIN_SIZE=${NODE_INSTANCE_WORKSPACE_MIN_SIZE:=1}
    NODE_INSTANCE_SERVICES_MAX_SIZE=${NODE_INSTANCE_WORKSPACE_MAX_SIZE:=1}
    NODE_INSTANCE_SERVICES_SPOT=${NODE_INSTANCE_WORKSPACE_SPOT:="true"}
    NODE_INSTANCE_SERVICES_VOLUME_SIZE=${NODE_INSTANCE_WORKSPACE_VOLUME_SIZE:="50"}
    NODE_INSTANCE_SERVICES_VOLUME_TYPE=${NODE_INSTANCE_WORKSPACE_VOLUME_TYPE:="gp2"}
    NODE_INSTANCE_SERVICES_IOPS=${NODE_INSTANCE_WORKSPACE_IOPS:="150"}
    NODE_INSTANCE_SERVICES_TYPE=${NODE_INSTANCE_WORKSPACE_TYPE:="t3a.xlarge"}
    NODE_INSTANCE_WORKSPACE_AUTOSCALER=${NODE_INSTANCE_WORKSPACE_AUTOSCALER:=false}
    NODE_INSTANCE_WORKSPACE_CLOUDWATCH_ENABLED=${NODE_INSTANCE_WORKSPACE_CLOUDWATCH_ENABLED:=false}

    NODE_INSTANCE_SERVICES_DESIRED_CAPACTIY=${NODE_INSTANCE_SERVICES_DESIRED_CAPACTIY:=1}
    NODE_INSTANCE_SERVICES_MIN_SIZE=${NODE_INSTANCE_SERVICES_MIN_SIZE:=1}
    NODE_INSTANCE_SERVICES_MAX_SIZE=${NODE_INSTANCE_SERVICES_MAX_SIZE:=1}
    NODE_INSTANCE_SERVICES_SPOT=${NODE_INSTANCE_SERVICES_SPOT:="true"}
    NODE_INSTANCE_SERVICES_VOLUME_SIZE=${NODE_INSTANCE_SERVICES_VOLUME_SIZE:="50"}
    NODE_INSTANCE_SERVICES_VOLUME_TYPE=${NODE_INSTANCE_SERVICES_VOLUME_TYPE:="gp2"}
    NODE_INSTANCE_SERVICES_IOPS=${NODE_INSTANCE_SERVICES_IOPS:="150"}
    NODE_INSTANCE_SERVICES_TYPE=${NODE_INSTANCE_SERVICES_TYPE:="t3a.xlarge"}
    NODE_INSTANCE_WORKSPACE_AUTOSCALER=${NODE_INSTANCE_SERVICES_AUTOSCALER:=false}
    NODE_INSTANCE_WORKSPACE_CLOUDWATCH_ENABLED=${NODE_INSTANCE_SERVICES_CLOUDWATCH_ENABLED:=false}


    export KUBECONFIG
    export CLUSTER_NAME
    export AWS_REGION
    export ACCOUNT_ID
    export CREATE_S3_BUCKET
    export CONTAINER_REGISTRY_BUCKET
    export NAMESPACE=${NAMESPACE:='default'}
}

function check_prerequisites() {
    EKSCTL_CONFIG=$1
    if [ ! -f "${EKSCTL_CONFIG}" ]; then
        echo "The eksctl configuration file ${EKSCTL_CONFIG} does not exist."
        exit 1
    else
        echo "Using eksctl configuration file: ${EKSCTL_CONFIG}"
    fi
    export EKSCTL_CONFIG

    if [ -z "${CERTIFICATE_ARN}" ]; then
        echo "Missing CERTIFICATE_ARN environment variable."
        exit 1;
    fi

    if [ -z "${DOMAIN}" ]; then
        echo "Missing DOMAIN environment variable."
        exit 1;
    fi

    AWS_CMD="aws"
    if [ -z "${AWS_PROFILE}" ]; then
        echo "Missing (optional) AWS profile."
        unset AWS_PROFILE
    else
        echo "Using the AWS profile: ${AWS_PROFILE}"
        AWS_CMD="aws --profile ${AWS_PROFILE}"
    fi
    export AWS_CMD

    if [ -z "${ROUTE53_ZONEID}" ]; then
        echo "Missing (optional) ROUTE53_ZONEID environment variable."
        echo "Please configure the CNAME with the URL of the load balancer manually."
    else
        echo "Using external-dns. No manual intervention required."
    fi
}

# Bootstrap AWS CDK - https://docs.aws.amazon.com/cdk/latest/guide/bootstrapping.html
function ensure_aws_cdk() {
    pushd /tmp > /dev/null 2>&1; /gitpod/node_modules/.bin/cdk bootstrap "aws://${ACCOUNT_ID}/${AWS_REGION}"; popd > /dev/null 2>&1
}

function install() {
    check_prerequisites "$1"
    variables_from_context
    echo accound id: "$ACCOUNT_ID"
    echo region: "$AWS_REGION"
    echo certificate: "$CERTIFICATE_ARN"
    ensure_aws_cdk

    yq e -i ".metadata.region = \"${AWS_REGION}\"" "${EKSCTL_CONFIG}"
    yq e -i ".availabilityZones[0] = \"${AWS_REGION}a\"" "${EKSCTL_CONFIG}"
    yq e -i ".availabilityZones[1] = \"${AWS_REGION}b\"" "${EKSCTL_CONFIG}"
    yq e -i ".availabilityZones[2] = \"${AWS_REGION}c\"" "${EKSCTL_CONFIG}"

    # Check the certificate exists
    if ! ${AWS_CMD} acm describe-certificate --certificate-arn "${CERTIFICATE_ARN}" --region "${AWS_REGION}" >/dev/null 2>&1; then
        echo The secret "${CERTIFICATE_ARN}" does not exist. Command was: aws acm describe-certificate --certificate-arn "${CERTIFICATE_ARN}" --region "${AWS_REGION}"
        exit 1
    fi

    # local CONFIG_FILE="${DIR}/gitpod-config.yaml"
    local CONFIG_FILE=$(cat <<EOF
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig
metadata:
  name: ${CLUSTER_NAME}
  region: ${AWS_REGION}
  version: 1.21

iam:
  withOIDC: true

  serviceAccounts:
    - metadata:
        name: aws-load-balancer-controller
        namespace: kube-system
      wellKnownPolicies:
        awsLoadBalancerController: true
    - metadata:
        name: ebs-csi-controller-sa
        namespace: kube-system
      wellKnownPolicies:
        ebsCSIController: true
    - metadata:
        name: cluster-autoscaler
        namespace: kube-system
      wellKnownPolicies:
        autoScaler: true

availabilityZones:
  - ${AWS_REGION}a
  - ${AWS_REGION}b
  - ${AWS_REGION}c

vpc:
  autoAllocateIPv6: false
  nat:
    gateway: Single
cloudWatch:
  clusterLogging:
    enableTypes: ["audit", "authenticator"]

privateCluster:
  enabled: false
  additionalEndpointServices:
    - autoscaling
    - logs

managedNodeGroups:
  - name: workspaces
    desiredCapacity: ${WORKSPACE_DESIRED_CAPACITY}
    minSize: ${WORKSPACE_MIN_SIZE}
    maxSize: ${WORKSPACE_MAX_SIZE}
    disableIMDSv1: false
    volumeSize: ${NODE_INSTANCE_WORKSPACE_VOLUME_SIZE}
    volumeType: ${NODE_INSTANCE_WORKSPACE_VOLUME_TYPE}
    volumeIOPS: ${NODE_INSTANCE_WORKSPACE_IOPS}
    volumeThroughput: ${NODE_INSTANCE_WORKSPACE_VOLUME_THROUGHPUT}
    ebsOptimized: ${NODE_INSTANCE_WORKSPACE_EBSOPTIMIZED}
    privateNetworking: true
    ami: ami-009935ddbb32a7f3c

    tags:
      # EC2 tags required for cluster-autoscaler auto-discovery
      k8s.io/cluster-autoscaler/enabled: "true"
      k8s.io/cluster-autoscaler/gitpod: "owned"
    iam:
      attachPolicyARNs: &attachPolicyARNs
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
        - arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy
        - arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy
        - arn:aws:iam::aws:policy/ElasticLoadBalancingFullAccess
        - arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
      withAddonPolicies: &withAddonPolicies
        albIngress: true
        autoScaler: ${NODE_INSTANCE_WORKSPACE_AUTOSCALER}
        cloudWatch: ${NODE_INSTANCE_WORKSPACE_CLOUDWATCH_ENABLED}
        certManager: true
        ebs: true
    overrideBootstrapCommand: |
      #!/bin/bash

      declare -a LABELS=(
        eks.amazonaws.com/nodegroup="services"
        gitpod.io/workload_workspace_services=true
        gitpod.io/workload_workspace_regular=true
        gitpod.io/workload_workspace_headless=true
      )

      export KUBELET_EXTRA_ARGS="$(printf -- "--max-pods=110 --node-labels=%s" $(IFS=$','; echo "${LABELS[*]}"))"
      /etc/eks/bootstrap.sh ${CLUSTER_NAME}

    spot: ${NODE_INSTANCE_WORKSPACE_SPOT}
    instanceSelector:
    instanceType: ${NODE_INSTANCE_WORKSPACE_TYPE}

  - name: services
    desiredCapacity: ${NODE_INSTANCE_SERVICES_DESIRED_CAPACTIY}
    minSize: ${NODE_INSTANCE_SERVICES_MIN_SIZE}
    maxSize: ${NODE_INSTANCE_SERVICES_MAX_SIZE}
    disableIMDSv1: false
    volumeSize: ${NODE_INSTANCE_SERVICES_VOLUME_SIZE}
    volumeType: ${NODE_INSTANCE_SERVICES_VOLUME_TYPE}
    volumeIOPS: ${NODE_INSTANCE_SERVICES_IOPS}
    volumeThroughput: ${NODE_INSTANCE_SERVICES_VOLUME_THROUGHPUT}
    ebsOptimized: ${NODE_INSTANCE_SERVICES_EBSOPTIMIZED}
    privateNetworking: true
    ami: ami-009935ddbb32a7f3c

    tags:
      k8s.io/cluster-autoscaler/enabled: "true"
      k8s.io/cluster-autoscaler/gitpod: "owned"
    iam:
      attachPolicyARNs: *attachPolicyARNs
      withAddonPolicies: *withAddonPolicies
    overrideBootstrapCommand: |
      #!/bin/bash

      declare -a LABELS=(
        eks.amazonaws.com/nodegroup="services"
        gitpod.io/workload_meta=true
        gitpod.io/workload_ide=true
      )

      export KUBELET_EXTRA_ARGS="$(printf -- "--max-pods=110 --node-labels=%s" $(IFS=$','; echo "${LABELS[*]}"))"
      /etc/eks/bootstrap.sh ${CLUSTER_NAME}

    spot: ${NODE_INSTANCE_SERVICES_SPOT}
    # https://eksctl.io/usage/instance-selector/
    #instanceSelector:
    instanceType: ${NODE_INSTANCE_SERVICES_TYPE}
EOF
)

    if ! eksctl get cluster "${CLUSTER_NAME}" > /dev/null 2>&1; then

        # Append user cluster settings

        yq e -i ".metadata.name = ${CLUSTER_NAME} ${EKSCTL_CONFIG}"
        yq e -i ".metadata.region = ${AWS_REGION} ${EKSCTL_CONFIG}"
        yq e -i ".availabilityZones[0] = ${AWS_REGION}a ${EKSCTL_CONFIG}"
        yq e -i ".availabilityZones[1] = ${AWS_REGION} ${EKSCTL_CONFIG}"
        yq e -i ".availabilityZones[2] = ${AWS_REGION}c ${EKSCTL_CONFIG}"

        # https://eksctl.io/usage/managing-nodegroups/
        eksctl create cluster --config-file "${EKSCTL_CONFIG}" --without-nodegroup
    else
        eksctl utils write-kubeconfig --cluster ${CLUSTER_NAME}
    fi

    if ! [ -f "/gitpod/gitpod-config.yaml" ]; then

        echo "No configuration found. Creating defaults."
        gitpod-installer init > gitpod-config.yaml
    fi

    # Append user cluster settings

    yq e -i ".certificate.name = \"https-certificates\"" "${CONFIG_FILE}"
    yq e -i ".domain = \"${DOMAIN}\"" "${CONFIG_FILE}"
    yq e -i ".database.inCluster = false" "${CONFIG_FILE}"
    yq e -i ".database.external.certificate.kind = \"secret\"" "${CONFIG_FILE}"
    yq e -i ".database.external.certificate.name = \"${MYSQL_GITPOD_SECRET}\"" "${CONFIG_FILE}"
    yq e -i '.workspace.runtime.containerdRuntimeDir = "/var/lib/containerd/io.containerd.runtime.v2.task/k8s.io"' "${CONFIG_FILE}"
    yq e -i ".containerRegistry.s3storage.bucket = \"${CONTAINER_REGISTRY_BUCKET}\"" "${CONFIG_FILE}"
    yq e -i ".containerRegistry.s3storage.certificate.kind = \"secret\"" "${CONFIG_FILE}"
    yq e -i ".containerRegistry.s3storage.certificate.name = \"${SECRET_STORAGE}\"" "${CONFIG_FILE}"
    yq e -i ".workspace.runtime.fsShiftMethod = \"shiftfs\"" "${CONFIG_FILE}"

    # Disable default AWS CNI provider.
    # The reason for this change is related to the number of containers we can have in ec2 instances
    # https://github.com/awslabs/amazon-eks-ami/blob/master/files/eni-max-pods.txt
    # https://docs.aws.amazon.com/eks/latest/userguide/pod-networking.html

    if [ -e "$(kubectl get ds -n kube-system aws-node -o yaml | yq e \"spec.template.spec.nodeSelector.non-calico\")" ]; then
        kubectl patch ds -n kube-system aws-node -p '{"spec":{"template":{"spec":{"nodeSelector":{"non-calico": "true"}}}}}'
        # Install Calico.
        kubectl apply -f https://docs.projectcalico.org/manifests/calico-vxlan.yaml
     else
        echo "Calico already enabled. Skipping installation."
    fi

    # Create secret with container registry credentials
    local SECRET
    if [ -n "${IMAGE_PULL_SECRET_FILE}" ] && [ -f "${IMAGE_PULL_SECRET_FILE}" ]; then
        SECRET=$(kubectl get secret generic gitpod-image-pull-secret)
        if ! [ "$SECRET" ]; then
            kubectl create secret generic gitpod-image-pull-secret \
                --from-file=.dockerconfigjson="${IMAGE_PULL_SECRET_FILE}" \
                --type=kubernetes.io/dockerconfigjson  >/dev/null 2>&1 || true
        else
            echo "Image pull secret already configured. Skipping."
        fi
    fi

    if ${AWS_CMD} iam get-role --role-name "${CLUSTER_NAME}-region-${AWS_REGION}-role-eksadmin" > /dev/null 2>&1; then
        echo "EKS access already configured."
        KUBECTL_ROLE_ARN=$(${AWS_CMD} iam get-role --role-name "${CLUSTER_NAME}-region-${AWS_REGION}-role-eksadmin" | jq -r .Role.Arn)
    else
        echo "Creating Role for EKS access"
        # Create IAM role and mapping to Kubernetes user and groups.
        POLICY=$(echo -n '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::'; echo -n "$ACCOUNT_ID"; echo -n ':root"},"Action":"sts:AssumeRole","Condition":{}}]}')
        KUBECTL_ROLE_ARN=$(${AWS_CMD} iam create-role \
            --role-name "${CLUSTER_NAME}-region-${AWS_REGION}-role-eksadmin" \
            --description "Kubernetes role (for AWS IAM Authenticator for Kubernetes)." \
            --assume-role-policy-document "$POLICY" \
            --output text \
            --query 'Role.Arn')
    fi
    export KUBECTL_ROLE_ARN

    # check if the identity mapping already exists
    # Manage IAM users and roles https://eksctl.io/usage/iam-identity-mappings/
    if ! eksctl get iamidentitymapping --cluster ${CLUSTER_NAME} --arn ${KUBECTL_ROLE_ARN} > /dev/null 2>&1; then
        echo "Creating mapping from IAM role ${KUBECTL_ROLE_ARN}"
        eksctl create iamidentitymapping \
            --cluster "${CLUSTER_NAME}" \
            --arn "${KUBECTL_ROLE_ARN}" \
            --username eksadmin \
            --group system:masters
    fi

    # Create cluster nodes defined in the configuration file
    eksctl create nodegroup --config-file=${EKSCTL_CONFIG}

    # Restart tigera-operator
    kubectl delete pod -n tigera-operator -l k8s-app=tigera-operator > /dev/null 2>&1

    MYSQL_GITPOD_USERNAME=${MYSQL_GITPOD_USERNAME:="gitpod"}
    MYSQL_GITPOD_PASSWORD=${MYSQL_GITPOD_PASSWORD:=$(openssl rand -hex 18)}
    MYSQL_GITPOD_SECRET=${MYSQL_GITPOD_SECRET:="mysql-gitpod-token"}
    MYSQL_GITPOD_ENCRYPTION_KEY=${MYSQL_GITPOD_ENCRYPTION_KEY:='[{"name":"general","version":1,"primary":true,"material":"4uGh1q8y2DYryJwrVMHs0kWXJlqvHWWt/KJuNi04edI="}]'}
    SECRET_STORAGE=${SECRET_STORAGE:="object-storage-gitpod-token"}

    # generated password cannot excede 41 characters (RDS limitation)
    SSM_KEY="/gitpod/cluster/${CLUSTER_NAME}/region/${AWS_REGION}"
    aws ssm put-parameter \
        --overwrite \
        --name ${SSM_KEY} \
        --type String \
        --value ${MYSQL_GITPOD_PASSWORD} \
        --region ${AWS_REGION} > /dev/null 2>&1

    # deploy CDK stacks
    npx cdk deploy \
        --context clusterName="${CLUSTER_NAME}" \
        --context region="${AWS_REGION}" \
        --context domain="${DOMAIN}" \
        --context certificatearn="${CERTIFICATE_ARN}" \
        --context identityoidcissuer="$(${AWS_CMD} eks describe-cluster --name "${CLUSTER_NAME}" --query "cluster.identity.oidc.issuer" --output text --region "${AWS_REGION}")" \
        --require-approval never \
        --outputs-file cdk-outputs.json \
        --all

    TLS termination is done in the ALB.
    cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: https-certificates
spec:
  dnsNames:
  - ${DOMAIN}
  - '*.${DOMAIN}'
  - '*.ws.${DOMAIN}'
  duration: 4380h0m0s
  issuerRef:
    group: cert-manager.io
    kind: Issuer
    name: ca-issuer
  secretName: https-certificates
EOF

    echo "Create database secret..."
    kubectl create secret generic "${MYSQL_GITPOD_SECRET}" \
        --from-literal=encryptionKeys="${MYSQL_GITPOD_ENCRYPTION_KEY}" \
        --from-literal=host="${MYSQL_GTITPOD_HOST:="$(jq -r '. | to_entries[] | select(.key | startswith("ServicesRDS")).value.MysqlEndpoint ' < cdk-outputs.json)"}" \
        --from-literal=password="${MYSQL_GITPOD_PASSWORD}" \
        --from-literal=port="3306" \
        --from-literal=username="${MYSQL_GITPOD_USERNAME}" \
        --dry-run=client -o yaml | \
        kubectl replace --force -f -

    echo "Create storage secret..."
    kubectl create secret generic "${SECRET_STORAGE}" \
        --from-literal=s3AccessKey="$(jq -r '. | to_entries[] | select(.key | startswith("ServicesRegistry")).value.AccessKeyId ' < cdk-outputs.json)" \
        --from-literal=s3SecretKey="$(jq -r '. | to_entries[] | select(.key | startswith("ServicesRegistry")).value.SecretAccessKey ' < cdk-outputs.json)" \
        --dry-run=client -o yaml | \
        kubectl replace --force -f -

    echo "Applying auth provider secret..."
    public_github=$(cat <<EOF
    data:
        auth-providers.json: |
            [{
                "id": "Public-GitHub",
                "host": "github.com",
                "type": "GitHub",
                "oauth": {
                "clientId": "'${GITHUB_CLIENT_ID}'",
                "clientSecret": "'${GITHUB_CLIENT_SECRET}'",
                "callBackUrl": "https://'${DOMAIN}'/auth/github/callback",
                "settingsUrl": "hhttps://mygithub.com/settings/applications/'${GITHUB_APPLICATION_ID}'"
                },
                "description": "",
                "icon": ""
            }]
EOF
)

    kubectl create secret generic --from-file=provider=/"${public_github}" public-github -n ${NAMESPACE}

    echo Proceeding to create deployment using the following configuration:
    echo "${CONFIG_FILE}"

    gitpod-installer \
        render \
        --config="${CONFIG_FILE}" > gitpod.yaml
    
    
    kubectl apply -f gitpod.yaml -n "${NAMESPACE}"

    # remove shiftfs-module-loader container.
    # TODO: remove once the container is removed from the installer
    kubectl patch daemonset ws-daemon --type json -p='[{"op": "remove",  "path": "/spec/template/spec/initContainers/3"}]'
    # Patch proxy service to remove use of cloud load balancer. In EKS we use ALB.
    kubectl patch service   proxy     --type merge --patch \
"$(cat <<EOF
spec:
  type: NodePort
EOF
)"

    # wait for update of the ingress status
    until [ -n "$(kubectl get ingress gitpod -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')" ]; do
        sleep 5
    done

    ALB_URL=$(kubectl get ingress gitpod -o json | jq -r .status.loadBalancer.ingress[0].hostname)
    if [ -n "${ALB_URL}" ];then
        printf '\nLoad balancer hostname: %s\n' "${ALB_URL}"
    fi
}

function uninstall() {
    check_prerequisites "$1"
    variables_from_context

    read -p "Are you sure you want to delete: Gitpod, Services/Registry, Services/RDS, Services, Addons, Setup (y/n)? " -n 1 -r
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if ! aws eks describe-cluster --name "${CLUSTER_NAME}" --region "${AWS_REGION}" > /dev/null; then
            exit 1
        fi

        KUBECTL_ROLE_ARN=$(aws iam get-role --role-name "${CLUSTER_NAME}-region-${AWS_REGION}-role-eksadmin" | jq -r .Role.Arn)
        export KUBECTL_ROLE_ARN

        SSM_KEY="/gitpod/cluster/${CLUSTER_NAME}/region/${AWS_REGION}"

        npx cdk destroy \
            --context clusterName="${CLUSTER_NAME}" \
            --context region="${AWS_REGION}" \
            --context domain="${DOMAIN}" \
            --context certificatearn="${CERTIFICATE_ARN}" \
            --context identityoidcissuer="$(aws eks describe-cluster --name "${CLUSTER_NAME}" --query "cluster.identity.oidc.issuer" --output text --region "${AWS_REGION}")" \
            --require-approval never \
            --force \
            --all \
        && npx cdk context --clear \
        && eksctl delete cluster "${CLUSTER_NAME}" \
        && aws ssm delete-parameter --name "${SSM_KEY}" --region "${AWS_REGION}"
    fi
}

function auth() {
    AUTHPROVIDERS_CONFIG=${1:="auth-providers-patch.yaml"}
    if [ ! -f "${AUTHPROVIDERS_CONFIG}" ]; then
        echo "The auth provider configuration file ${AUTHPROVIDERS_CONFIG} does not exist."
        exit 1
    else
        echo "Using the auth providers configuration file: ${AUTHPROVIDERS_CONFIG}"
    fi

    # Patching the configuration with the user auth provider/s
    kubectl --kubeconfig .kubeconfig patch configmap auth-providers-config --type merge --patch "$(cat ${AUTHPROVIDERS_CONFIG})"
    # Restart the server component
    kubectl --kubeconfig .kubeconfig rollout restart deployment/server
}

function main() {
    if [[ $# -ne 1 ]]; then
        echo "Usage: $0 [--install|--uninstall]"
        exit
    fi

    case $1 in
        '--install')
            install "eks-cluster.yaml"
        ;;
        '--uninstall')
            uninstall "eks-cluster.yaml"
        ;;
        '--auth')
            auth "auth-providers-patch.yaml"
        ;;
        *)
            echo "Unknown command: $1"
            echo "Usage: $0 [--install|--uninstall]"
        ;;
    esac
    echo "done"
}

main "$@"
