FROM ubuntu:latest AS curl

ARG GITPOD_VERSION="2022.02.0"

RUN apt-get update; apt-get install curl -y

RUN curl -fsSL https://github.com/mikefarah/yq/releases/download/v4.12.0/yq_linux_amd64 -o /usr/local/bin/yq 

RUN curl -fsSL https://github.com/weaveworks/eksctl/releases/download/v0.75.0/eksctl_Linux_amd64.tar.gz | tar -xz -C /usr/local/bin

RUN curl -fsSL "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl" -o /usr/local/bin/kubectl

RUN curl -fsSL https://github.com/kubernetes-sigs/aws-iam-authenticator/releases/download/v0.5.3/aws-iam-authenticator_0.5.3_linux_amd64 -o /usr/local/bin/aws-iam-authenticator

RUN curl -fsSL https://github.com/gitpod-io/gitpod/releases/download/${GITPOD_VERSION}/gitpod-installer-linux-amd64 -o /usr/local/bin/gitpod-installer



FROM alpine:edge

COPY --from=curl /usr/local/bin/yq /usr/local/bim/yq
RUN chmod +x /usr/local/bim/yq
COPY --from=curl /usr/local/bin/eksctl /usr/local/bin/eksctl
RUN chmod +x /usr/local/bin/eksctl
COPY --from=curl /usr/local/bin/kubectl /usr/local/bin/kubectl
RUN chmod +x /usr/local/bin/kubectl
COPY --from=curl /usr/local/bin/aws-iam-authenticator /usr/local/bin/aws-iam-authenticator
RUN chmod +x /usr/local/bin/aws-iam-authenticator
COPY --from=curl /usr/local/bin/gitpod-installer /usr/local/bin/gitpod-installer
RUN chmod +x /usr/local/bin/gitpod-installer


RUN apk add --no-cache \
    bash \
    curl \
    nodejs \
    python3 \
    py3-pip \
    jq \
    npm \
    yq \
    openssl \
  && pip3 install --upgrade pip \
  && pip3 install \
    awscli \
  && rm -rf /root/.cache

WORKDIR /gitpod

COPY ami ami
COPY bin bin
COPY lib lib
COPY cdk.json cdk.json
COPY package.json package.json
COPY package-lock.json package-lock.json
COPY setup.sh setup.sh


# RUN npm install -g aws-cdk ts-node
RUN npm i
# RUN yarn build

ENTRYPOINT ["bash","setup.sh"]