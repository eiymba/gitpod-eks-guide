import { KubernetesManifest } from '@aws-cdk/aws-eks';
import { loadYaml, readYamlDocument } from './utils.js';
import { StackProps } from '@aws-cdk/core';
import { importCluster } from './cluster-utils.js';
import * as cdk from '@aws-cdk/core';
import * as eks from '@aws-cdk/aws-eks';

export class Jaeger extends cdk.Construct {
    constructor(scope: cdk.Construct, id: string, props: StackProps) {
        super(scope, id);

        const cluster = importCluster(this, process.env.CLUSTER_NAME);

        const helmChart = cluster.addHelmChart('jaeger-operator-chart', {
            chart: 'jaeger-operator',
            release: 'jaeger-operator',
            repository: 'https://jaegertracing.github.io/helm-charts',
            namespace: 'jaeger-operator',
            version: '2.27.0',
            wait: true,
            values: {
                rbac: {
                    clusterRole: true,
                },
                "affinity": {
                    "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [
                                {
                                    "matchExpressions": [
                                        {
                                            "key": "gitpod.io/workload_meta",
                                            "operator": "In",
                                            "values": ["true"]
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                }
            },
        });

        const doc = readYamlDocument(process.cwd() + '/lib/charts/assets/jaeger-gitpod.yaml');
        const gitpodJaeger = new KubernetesManifest(cluster.stack, "gitpod-jaeger", {
            cluster,
            overwrite: true,
            manifest: [loadYaml(doc)],
        });
        gitpodJaeger.node.addDependency(helmChart);
    }
}
