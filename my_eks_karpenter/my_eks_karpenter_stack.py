from constructs import Construct
from aws_cdk import (
    Duration,
    Stack,
    Tags,
    CfnJson,
    aws_eks as eks,
    aws_ec2 as ec2,
    aws_iam as iam,
    aws_kms as kms,
)
from aws_cdk.lambda_layer_kubectl_v31 import KubectlV31Layer
import cdk_eks_karpenter
import os
import yaml


class MyEksKarpenterStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.cluster_name = "eks-karpenter-cluster"
        self.vpc_name = "ekskarpentervpc"

        vpc = ec2.Vpc(
            self, "CdkEksKarpenterVpc", vpc_name=self.vpc_name, ip_addresses=ec2.IpAddresses.cidr("10.0.0.0/16"),
            max_azs=3, nat_gateways=1, enable_dns_hostnames=True, enable_dns_support=True,
            subnet_configuration=[
                ec2.SubnetConfiguration(subnet_type=ec2.SubnetType.PUBLIC, name="public_subnets", cidr_mask=24), 
                ec2.SubnetConfiguration(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS, name="private_subnets", cidr_mask=24),
                ec2.SubnetConfiguration(subnet_type=ec2.SubnetType.PRIVATE_ISOLATED, name="database_subnets", cidr_mask=28, reserved=True)
            ],
        )

        Tags.of(vpc).add("Environment", "dev")
        Tags.of(vpc).add("CDK", "true")

        private_subnets = vpc._select_subnet_objects(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        Tags.of(private_subnets[0]).add("karpenter.sh/discovery", self.cluster_name)
        Tags.of(private_subnets[1]).add("karpenter.sh/discovery", self.cluster_name)

        mySecurityGroup = ec2.SecurityGroup(self, "SecurityGroup", vpc=vpc,
                                            description='Allow access to cluster', allow_all_outbound=True, security_group_name="ekskarpentervpcsg")
        
        mySecurityGroup.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(80), 'allow http from the world');
        mySecurityGroup.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443), 'allow https access from the world');

        kms_key = kms.Key(self, "MyKey", enable_key_rotation=True, rotation_period=Duration.days(180), description="EKS Cluster",
                          alias=f"eks/{self.cluster_name}", pending_window=Duration.days(7),
                          admins=[
                              iam.ArnPrincipal(f"arn:aws:iam::{iam.AccountRootPrincipal().account_id}:user/Aws_admin_Sani"),
                              iam.ArnPrincipal(f"arn:aws:iam::{iam.AccountRootPrincipal().account_id}:user/terraform-user"),
                          ],)
        
        Tags.of(kms_key).add("Environment", "dev")
        Tags.of(kms_key).add("CDK", "true")
        
        clusterrole = iam.Role(self, "ClusterNodeRole",
            assumed_by=iam.ServicePrincipal("eks.amazonaws.com"), role_name="clusternoderole",
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSClusterPolicy"),
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEKSVPCResourceController")
            ]
        )
        
        cluster = eks.Cluster(self, 'new-eks-karpenter', version=eks.KubernetesVersion.V1_31,
                                     cluster_name=self.cluster_name, endpoint_access=eks.EndpointAccess.PUBLIC_AND_PRIVATE,
                                     vpc=vpc, authentication_mode=eks.AuthenticationMode.API_AND_CONFIG_MAP,
                                     kubectl_layer=KubectlV31Layer(self, "kubectl"),
                                     role=clusterrole,
                                     alb_controller=eks.AlbControllerOptions(version=eks.AlbControllerVersion.V2_8_2),
                                     vpc_subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)],
                                     bootstrap_cluster_creator_admin_permissions=True, default_capacity=0,
                                     secrets_encryption_key=kms_key, 
                                     tags={
                                         "Environment": "dev",
                                         "CDK": "true",
                                         "karpenter.sh/discovery": self.cluster_name,
                                     },
                                     )
        
        cluster.add_nodegroup_capacity("custom-node-group", nodegroup_name="node-grp-1",
            instance_types=[ec2.InstanceType("m5.large"), ec2.InstanceType("m5n.large"), ec2.InstanceType("m5zn.large"), ec2.InstanceType("t3.medium"), ec2.InstanceType("t3.small")],
            ami_type=eks.NodegroupAmiType.AL2023_X86_64_STANDARD,
            min_size=0, desired_size=2, max_size=3, disk_size=20,
            # taints=[eks.TaintSpec(
            #     effect=eks.TaintEffect.NO_SCHEDULE,
            #     key="CriticalAddonsOnly",
            #     value="true"
            # )
            # ],   
        )

        issuer_hostpath_ebs = CfnJson(
            self, "IssuerHostPathEbs",
            value={
                f"{cluster.open_id_connect_provider.open_id_connect_provider_issuer}:sub": 
                "system:serviceaccount:kube-system:ebs-csi-controller-sa"
            }
        )

        ebs_csi_trust_policy=iam.FederatedPrincipal(
            federated=cluster.open_id_connect_provider.open_id_connect_provider_arn,
            conditions={
                "StringEquals": issuer_hostpath_ebs
            },
            assume_role_action="sts:AssumeRoleWithWebIdentity"
        )

        ebs_csi_driver_role=iam.Role(self, "EbsCsiDriverRole",
            managed_policies=[iam.ManagedPolicy.from_managed_policy_arn(self, "EBSCSIDriverPolicy", managed_policy_arn="arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"),
                              ],
            assumed_by=ebs_csi_trust_policy,
        )

        ebs_csi_driver_role.add_to_policy(iam.PolicyStatement(
            actions=["kms:Decrypt", "kms:GenerateDataKeyWithoutPlaintext", "kms:CreateGrant"],
            resources=["*"]
        ))
        
        ebs_csi_addon = eks.CfnAddon(self, "eks-ebs-csi-driver",
            cluster_name=cluster.cluster_name,
            addon_name="aws-ebs-csi-driver",
            addon_version="v1.38.1-eksbuild.1",
            preserve_on_delete=False,
            service_account_role_arn=ebs_csi_driver_role.role_arn
        )

        eks.Addon(self, "CorednsAddon", cluster=cluster, addon_name="coredns", preserve_on_delete=False,)
        eks.Addon(self, "kubeAddon", cluster=cluster, addon_name="kube-proxy", preserve_on_delete=False,)
        eks.Addon(self, "vpcAddon", cluster=cluster, addon_name="vpc-cni", preserve_on_delete=False,)
        eks.Addon(self, "podidentityAddon", cluster=cluster, addon_name="eks-pod-identity-agent", preserve_on_delete=False,)

        access_entry = eks.AccessEntry(self, "MyAccessEntry",
            access_policies=[
                eks.AccessPolicy.from_access_policy_name("AmazonEKSClusterAdminPolicy",
                                                         access_scope_type=eks.AccessScopeType.CLUSTER)
            ],
            cluster=cluster,
            principal=f"arn:aws:iam::{iam.AccountRootPrincipal().account_id}:user/Aws_admin_Sani",
        )

        access_entry1 = eks.AccessEntry(self, "MyEntry",
            access_policies=[
                eks.AccessPolicy.from_access_policy_name("AmazonEKSClusterAdminPolicy",
                                                         access_scope_type=eks.AccessScopeType.CLUSTER)
            ],
            cluster=cluster,
            principal=f"arn:aws:iam::{iam.AccountRootPrincipal().account_id}:user/terraform-user",
        )
        
        cluster.add_fargate_profile("fargateappprofile", selectors=[eks.Selector(namespace="fargateapp")])

        karpenter = cdk_eks_karpenter.Karpenter(self, id="karpenter", cluster=cluster, version='1.0.8', namespace='kube-system',)

        karpenter.add_ec2_node_class("node-class-default", ec2_node_class_spec={
                 "amiFamily": "AL2023",
                 "role": karpenter.node_role.role_name,
                 "subnetSelectorTerms": [{
                      "tags": {
                           "karpenter.sh/discovery": self.cluster_name
                      }
                 }],
                 "securityGroupSelectorTerms": [{
                      "tags": {
                           "aws:eks:cluster-name": self.cluster_name
                      }
                 }],
                 "amiSelectorTerms": [{
                      "id": "ami-086d1d1587a61ea1f"
                 },],
                 "tags": {
                      "karpenter.sh/discovery": self.cluster_name
                 },
        })

        karpenter.add_node_pool("node-pool-default", node_pool_spec={
            "template": {
                "spec": {
                    "nodeClassRef": {
                        "group": "karpenter.k8s.aws",
                        "kind": "EC2NodeClass",
                        "name": "node-class-default"
                    },
                    "requirements": [
                        {
                            "key": "kubernetes.io/arch",
                            "operator": "In",
                            "values": ["amd64"]
                        },
                        {
                            "key": "kubernetes.io/os",
                            "operator": "In",
                            "values": ["linux"]
                        },
                        {
                            "key": "karpenter.sh/capacity-type",
                            "operator": "In",
                            "values": ["spot", "on-demand"]
                        },
                        {
                            "key": "karpenter.k8s.aws/instance-category",
                            "operator": "In",
                            "values": ["c", "m", "r", "t"]
                        },
                        {
                            "key": "karpenter.k8s.aws/instance-generation",
                            "operator": "Gt",
                            "values": ["2"]
                        },
                        {
                            "key": "karpenter.k8s.aws/instance-cpu",
                            "operator": "In",
                            "values": ["2", "4", "8", "16", "32"]
                        },
                        {
                            "key": "karpenter.k8s.aws/instance-hypervisor",
                            "operator": "In",
                            "values": ["nitro"]
                        },
                    ],
                    "expireAfter": "72h",
                }
            },
            "limits": {
                "cpu": 1000,
            },
            "disruption": {
                "consolidationPolicy": "WhenEmptyOrUnderutilized",
                "consolidateAfter": "30s"
            }
        })

        karpenter.add_managed_policy_to_karpenter_role(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))

        argocd = eks.HelmChart(self, "argocdchart",
            cluster=cluster,
            chart="argo-cd",
            repository="https://argoproj.github.io/argo-helm",
            namespace="argocd",
            version="3.35.4",
            values={
                "global": {
                    "image": {
                        "tag": "v2.6.6"
                    }
                },
                "server": {
                    "extraArgs": ["--insecure"],
                    "ingress": {
                        "enabled": "true",
                        "controller": "aws",
                        "annotations": {
                            "alb.ingress.kubernetes.io/scheme": "internet-facing",
                             "alb.ingress.kubernetes.io/target-type": "ip",
                             "alb.ingress.kubernetes.io/group.name": "mscodes",
                        },
                        "ingressClassName": "alb",
                        "path": "/",
                        "aws": {
                            "serviceType": "ClusterIP"
                        }
                    }
                }
            }
        )

        argocd.node.add_dependency(karpenter)

        fargate_app_label = {"app": "fargate-app"}

        fargate_namespace = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "fargateapp"
            }
        }

        fargate_deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "fargateapp",
                         "namespace": "fargateapp"},
            "spec": {
                "replicas": 2,
                "selector": {"matchLabels": fargate_app_label},
                "template": {
                    "metadata": {"labels": fargate_app_label},
                    "spec": {
                        "tolerations": [{
                            "key": "eks.amazonaws.com/compute-type",
                            "operator": "Equal",
                            "value": "fargate",
                            "effect": "NoSchedule",
                        }],
                        "containers": [{
                            "name": "fargate-app",
                            "image": "public.ecr.aws/j0l0w3g7/node-ecr-repo:latest",
                            "ports": [{"containerPort": 3000}],
                            "resources": {
                                "requests": {
                                    "memory": "1024Mi",
                                    "cpu": "1000m"
                                },
                                "limits": {
                                    "memory": "2048Mi",
                                    "cpu": "2000m"
                                }
                            }
                        }
                        ]
                    }
                }
            }
        }

        fargate_service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "fargateapp",
                         "namespace": "fargateapp"},
            "spec": {
                "type": "NodePort",
                "ports": [{"port": 3000, "targetPort": 3000}],
                "selector": fargate_app_label
            }
        }

        fargate_ingress = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {"namespace": "fargateapp",
                         "name": "ingress-fargateapp",
                         "annotations": {
                             "alb.ingress.kubernetes.io/scheme": "internet-facing",
                             "alb.ingress.kubernetes.io/target-type": "ip",
                             "alb.ingress.kubernetes.io/group.name": "mscodes",
                         }
            },
            "spec": {
                "ingressClassName": "alb",
                # Configure the created loadbalancer to Route 53 and then add host 
                # "rules": [{"host": "fargate.mscodesdigitalsolutions.com", "http": {"paths": [{"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "fargateapp", "port": {"number": 3000}}}}]}}]
                "rules": [{"http": {"paths": [{"path": "/", "pathType": "Prefix", "backend": {"service": {"name": "fargateapp", "port": {"number": 3000}}}}]}}]
            }
        }

        fargate_manifest = eks.KubernetesManifest(self, "fargate-app",
            cluster=cluster,
            manifest=[fargate_namespace, fargate_deployment, fargate_service, fargate_ingress],
            ingress_alb=True,
            ingress_alb_scheme=eks.AlbScheme.INTERNET_FACING,
            skip_validation=False,
            overwrite=True,
            prune=True,
        )

        fargate_manifest.node.add_dependency(cluster.alb_controller)
        fargate_manifest.node.add_dependency(karpenter, cluster)

        # namespace_vault = {
        #     "apiVersion": "v1",
        #     "kind": "Namespace",
        #     "metadata": {
        #         "name": "vault"
        #     }
        # }

        # eks_creds = {
        #     "apiVersion": "v1",
        #     "kind": "Secret",
        #     "metadata": {
        #         "name": "eks-creds",
        #         "namespace": "vault"
        #     },
        #     "type": "Opaque",
        #     "data": {
        #         # consider creating a new access key and using it here
        #         # instead of using environment variables.
        #         "AWS_ACCESS_KEY_ID": os.environ["AWS_ACCESS_KEY_ID"],
        #         "AWS_SECRET_ACCESS_KEY": os.environ["AWS_SECRET_ACCESS_KEY"]
        #     }
        # }

        # vault_setup = eks.KubernetesManifest(self, "hello-vault",
        #     cluster=cluster,
        #     ingress_alb=True,
        #     ingress_alb_scheme=eks.AlbScheme.INTERNET_FACING,
        #     manifest=[namespace_vault, eks_creds],
        #     overwrite=True,
        # )

        app_label = {"app": "my-app"}

        namespace = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "myapp"
            }
        }

        deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "my-app",
                         "namespace": "myapp"},
            "spec": {
                "replicas": 3,
                "selector": {"matchLabels": app_label},
                "template": {
                    "metadata": {"labels": app_label},
                    "spec": {
                        "containers": [{
                            "name": "my-app",
                            "image": "public.ecr.aws/j0l0w3g7/max-ecr-repo:latest",
                            "ports": [{"containerPort": 80}],
                            "resources": {
                                "requests": {
                                    "memory": "64Mi",
                                    "cpu": "250m"
                                },
                                "limits": {
                                    "memory": "128Mi",
                                    "cpu": "5000m"
                                }
                            }
                        }
                        ]
                    }
                }
            }
        }

        service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "my-app",
                         "namespace": "myapp"},
            "spec": {
                "type": "NodePort",
                "ports": [{"port": 80, "targetPort": 80}],
                "selector": app_label
            }
        }

        ingress = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {"namespace": "myapp",
                         "name": "ingress-myapp",
                         "annotations": {
                             "alb.ingress.kubernetes.io/scheme": "internet-facing",
                             "alb.ingress.kubernetes.io/target-type": "ip",
                             "alb.ingress.kubernetes.io/group.name": "mscodes",
                         }
            },
            "spec": {
                "ingressClassName": "alb",
                "rules": [{
                    # Configure the created loadbalancer to Route 53 and then add host 
                    # "host": "myapp.mscodesdigitalsolutions.com",
                    "http": {
                        "paths": [{
                            "pathType": "Prefix",
                            "path": "/",
                            "backend": {
                                "service": {
                                    "name": "my-app",
                                    "port": {
                                        "number": 80
                                    }
                                }
                            }
                        }]
                    }
                }]
            }
        }

        node_app_label = {"app": "mynode-app"}

        nodeapp_namespace = {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": "nodeapp"
            }
        }

        nodeapp_deployment = {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": "mynode-app",
                         "namespace": "nodeapp"},
            "spec": {
                "replicas": 1,
                "selector": {"matchLabels": node_app_label},
                "template": {
                    "metadata": {"labels": node_app_label},
                    "spec": {
                        "containers": [{
                            "name": "myapp",
                            "image": "public.ecr.aws/j0l0w3g7/node-ecr-repo:latest",
                            "ports": [{"containerPort": 3000}],
                            "resources": {
                                "requests": {
                                    "memory": "1024Mi",
                                    "cpu": "1000m"
                                },
                                "limits": {
                                    "memory": "2048Mi",
                                    "cpu": "2000m"
                                }
                            }
                        }
                        ]
                    }
                }
            }
        }

        nodeapp_service = {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "mynode",
                         "namespace": "nodeapp"},
            "spec": {
                "type": "ClusterIP",
                "ports": [{"port": 3000,}],
                "selector": node_app_label
            }
        }

        nodeapp_ingress = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "Ingress",
            "metadata": {"namespace": "nodeapp",
                         "name": "ingress-nodeapp",
                         "annotations": {
                             "alb.ingress.kubernetes.io/scheme": "internet-facing",
                             "alb.ingress.kubernetes.io/target-type": "ip",
                             "alb.ingress.kubernetes.io/group.name": "mscodes",
                         }
            },
            "spec": {
                "ingressClassName": "alb",
                "rules": [{
                    # Configure the created loadbalancer to Route 53 and then add host 
                    # "host": "nodeapp.mscodesdigitalsolutions.com",
                    "http": {
                        "paths": [{
                            "pathType": "Prefix",
                            "path": "/",
                            "backend": {
                                "service": {
                                    "name": "mynode",
                                    "port": {
                                        "number": 3000
                                    }
                                }
                            }
                        }]
                    }
                }]
            }
        }

        eks.KubernetesManifest(self, "hello-kub",
            cluster=cluster,
            manifest=[namespace, service, deployment, ingress, nodeapp_namespace, nodeapp_service, nodeapp_deployment, nodeapp_ingress],
            ingress_alb=True,
            ingress_alb_scheme=eks.AlbScheme.INTERNET_FACING,
            skip_validation=False,
            overwrite=True,
            prune=True,
        ).node.add_dependency(cluster.alb_controller)

        storage_class = cluster.add_manifest("gp3-storageclass", {
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": {"name": "gp3-default",
                         "annotations": {
                             "storageclass.kubernetes.io/is-default-class": "true",
                         }
            },
            "provisioner": "ebs.csi.aws.com",
            "reclaimPolicy": "Delete",
            "volumeBindingMode": "WaitForFirstConsumer",
            "allowVolumeExpansion": True,
            "parameters": {
                "type": "gp3",
                "fsType": "ext4",
                "encrypted": "true",
                "kmsKeyId": kms_key.key_id
            },
        })

        storage_class.node.add_dependency(cluster)

        
    #     sa = self.create_service_account(service_account_name="ebs-csi-controller-sa", 
    #             namespace="kube-system", pod_identity=True,
    #             cluster=cluster, policy=iam.ManagedPolicy.from_managed_policy_arn(self, "ebs-csi-policy", managed_policy_arn="arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy")
    #     )
        
    #     # create the AddOn using L2
    #     ebs_csi_addon = eks.Addon(self, "ebs-csi-addon",
    #         addon_name="aws-ebs-csi-driver",
    #         addon_version="v1.38.1-eksbuild.1",
    #         cluster=cluster,
    #         preserve_on_delete=False,
    #     )
        
    #     # add_property_override with PodIdentityAssociations
    #     cfnaddon = ebs_csi_addon.node.default_child
    #     cfnaddon.add_property_override("ResolveConflicts", 'OVERWRITE')
    #     # cfnaddon.add_property_override("ServiceAccountRoleArn", sa.role.role_arn) uncomment for IRSA 
    #     cfn_eks_pod_identity_agent_addon = cluster.node.try_find_child("EksPodIdentityAgentAddon")
    #     ebs_csi_addon.node.add_dependency(sa, cfn_eks_pod_identity_agent_addon)

    # def create_service_account(self, service_account_name: str, namespace: str, pod_identity: bool, cluster: eks.Cluster, policy: iam.ManagedPolicy):
    #     sa = eks.ServiceAccount(self, f"ServiceAccount-{service_account_name}",
    #         cluster=cluster,
    #         name=service_account_name,
    #         namespace=namespace,
    #         identity_type=eks.IdentityType.POD_IDENTITY if pod_identity is True else eks.IdentityType.IRSA
    #     )
    #     sa.role.add_managed_policy(policy=policy)
    #     return sa
        