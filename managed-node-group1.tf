provider "aws" {
  region = local.region
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {}
data "aws_partition" "current" {}

locals {
  name            = "ex-${replace(basename(path.cwd), "_", "-")}"
  cluster_version = "1.27"
  region          = "us-gov-east-1"

  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
  part       = data.aws_partition.current.partition

  tags = {
    Example    = local.name
    GithubRepo = "terraform-aws-eks"
    GithubOrg  = "terraform-aws-modules"
  }
}

################################################################################
# EKS Module
################################################################################

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "19.20.0"

  cluster_name                   = local.name
  cluster_version                = local.cluster_version
  cluster_endpoint_public_access = true

  # IPV6
  cluster_ip_family = "ipv6"

  # We are using the IRSA created below for permissions
  # However, we have to deploy with the policy attached FIRST (when creating a fresh cluster)
  # and then turn this off after the cluster/node group is created. Without this initial policy,
  # the VPC CNI fails to assign IPs and nodes cannot join the cluster
  # See https://github.com/aws/containers-roadmap/issues/1666 for more context
  # TODO - remove this policy once AWS releases a managed version similar to AmazonEKS_CNI_Policy (IPv4)
  create_cni_ipv6_iam_policy = true

  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent              = true
      before_compute           = true
      service_account_role_arn = module.vpc_cni_irsa.iam_role_arn
      configuration_values = jsonencode({
        env = {
          # Reference docs https://docs.aws.amazon.com/eks/latest/userguide/cni-increase-ip-addresses.html
          ENABLE_PREFIX_DELEGATION = "true"
          WARM_PREFIX_TARGET       = "1"
        }
      })
    }
  }

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.intra_subnets

  manage_aws_auth_configmap = true

  eks_managed_node_group_defaults = {
    ami_type       = "AL2_x86_64"
    instance_types = ["m6i.large", "m5.large", "m5n.large", "m5zn.large"]

    # We are using the IRSA created below for permissions
    # However, we have to deploy with the policy attached FIRST (when creating a fresh cluster)
    # and then turn this off after the cluster/node group is created. Without this initial policy,
    # the VPC CNI fails to assign IPs and nodes cannot join the cluster
    # See https://github.com/aws/containers-roadmap/issues/1666 for more context
    iam_role_attach_cni_policy = true
  }

  eks_managed_node_groups = {
    # Default node group - as provided by AWS EKS
    default_node_group = {
      # By default, the module creates a launch template to ensure tags are propagated to instances, etc.,
      # so we need to disable it to use the default template provided by the AWS EKS managed node group service
      use_custom_launch_template = false

      disk_size = 50

      # Remote access cannot be specified with a launch template
      remote_access = {
        ec2_ssh_key               = module.key_pair.key_pair_name
        source_security_group_ids = [aws_security_group.remote_access.id]
      }
    }

  #   # Default node group - as provided by AWS EKS using Bottlerocket
  #   bottlerocket_default = {
  #     # By default, the module creates a launch template to ensure tags are propagated to instances, etc.,
  #     # so we need to disable it to use the default template provided by the AWS EKS managed node group service
  #     use_custom_launch_template = false

  #     ami_type = "BOTTLEROCKET_x86_64"
  #     platform = "bottlerocket"
  #   }

  #   # Adds to the AWS provided user data
  #   bottlerocket_add = {
  #     ami_type = "BOTTLEROCKET_x86_64"
  #     platform = "bottlerocket"

  #     # This will get added to what AWS provides
  #     bootstrap_extra_args = <<-EOT
  #       # extra args added
  #       [settings.kernel]
  #       lockdown = "integrity"
  #     EOT
  #   }

  #   # Custom AMI, using module provided bootstrap data
  #   bottlerocket_custom = {
  #     # Current bottlerocket AMI
  #     ami_id   = data.aws_ami.eks_default_bottlerocket.image_id
  #     platform = "bottlerocket"

  #     # Use module user data template to bootstrap
  #     enable_bootstrap_user_data = true
  #     # This will get added to the template
  #     bootstrap_extra_args = <<-EOT
  #       # The admin host container provides SSH access and runs with "superpowers".
  #       # It is disabled by default, but can be disabled explicitly.
  #       [settings.host-containers.admin]
  #       enabled = false

  #       # The control host container provides out-of-band access via SSM.
  #       # It is enabled by default, and can be disabled if you do not expect to use SSM.
  #       # This could leave you with no way to access the API and change settings on an existing node!
  #       [settings.host-containers.control]
  #       enabled = true

  #       # extra args added
  #       [settings.kernel]
  #       lockdown = "integrity"

  #       [settings.kubernetes.node-labels]
  #       label1 = "foo"
  #       label2 = "bar"

  #       [settings.kubernetes.node-taints]
  #       dedicated = "experimental:PreferNoSchedule"
  #       special = "true:NoSchedule"
  #     EOT
  #   }

  #   # Use a custom AMI
  #   custom_ami = {
  #     ami_type = "AL2_ARM_64"
  #     # Current default AMI used by managed node groups - pseudo "custom"
  #     ami_id = data.aws_ami.eks_default_arm.image_id

  #     # This will ensure the bootstrap user data is used to join the node
  #     # By default, EKS managed node groups will not append bootstrap script;
  #     # this adds it back in using the default template provided by the module
  #     # Note: this assumes the AMI provided is an EKS optimized AMI derivative
  #     enable_bootstrap_user_data = true

  #     instance_types = ["t4g.medium"]
  #   }

  #   # Complete
  #   complete = {
  #     name            = "complete-eks-mng"
  #     use_name_prefix = true

  #     subnet_ids = module.vpc.private_subnets

  #     min_size     = 1
  #     max_size     = 7
  #     desired_size = 1

  #     ami_id                     = data.aws_ami.eks_default.image_id
  #     enable_bootstrap_user_data = true

  #     pre_bootstrap_user_data = <<-EOT
  #       export FOO=bar
  #     EOT

  #     post_bootstrap_user_data = <<-EOT
  #       echo "you are free little kubelet!"
  #     EOT

  #     capacity_type        = "SPOT"
  #     force_update_version = true
  #     instance_types       = ["m6i.large", "m5.large", "m5n.large", "m5zn.large"]
  #     labels = {
  #       GithubRepo = "terraform-aws-eks"
  #       GithubOrg  = "terraform-aws-modules"
  #     }

  #     taints = [
  #       {
  #         key    = "dedicated"
  #         value  = "gpuGroup"
  #         effect = "NO_SCHEDULE"
  #       }
  #     ]

  #     update_config = {
  #       max_unavailable_percentage = 33 # or set `max_unavailable`
  #     }

  #     description = "EKS managed node group example launch template"

  #     ebs_optimized           = true
  #     disable_api_termination = false
  #     enable_monitoring       = true

  #     block_device_mappings = {
  #       xvda = {
  #         device_name = "/dev/xvda"
  #         ebs = {
  #           volume_size           = 75
  #           volume_type           = "gp3"
  #           iops                  = 3000
  #           throughput            = 150
  #           encrypted             = true
  #           kms_key_id            = module.ebs_kms_key.key_arn
  #           delete_on_termination = true
  #         }
  #       }
  #     }

  #     metadata_options = {
  #       http_endpoint               = "enabled"
  #       http_tokens                 = "required"
  #       http_put_response_hop_limit = 2
  #       instance_metadata_tags      = "disabled"
  #     }

  #     create_iam_role          = true
  #     iam_role_name            = "eks-managed-node-group-complete-example"
  #     iam_role_use_name_prefix = false
  #     iam_role_description     = "EKS managed node group complete example role"
  #     iam_role_tags = {
  #       Purpose = "Protector of the kubelet"
  #     }
  #     iam_role_additional_policies = {
  #       AmazonEC2ContainerRegistryReadOnly = "arn:${local.part}:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  #       additional                         = aws_iam_policy.node_additional.arn
  #     }

  #     schedules = {
  #       scale-up = {
  #         min_size     = 2
  #         max_size     = "-1" # Retains current max size
  #         desired_size = 2
  #         start_time   = "2023-03-05T00:00:00Z"
  #         end_time     = "2024-03-05T00:00:00Z"
  #         time_zone    = "Etc/GMT+0"
  #         recurrence   = "0 0 * * *"
  #       },
  #       scale-down = {
  #         min_size     = 0
  #         max_size     = "-1" # Retains current max size
  #         desired_size = 0
  #         start_time   = "2023-03-05T12:00:00Z"
  #         end_time     = "2024-03-05T12:00:00Z"
  #         time_zone    = "Etc/GMT+0"
  #         recurrence   = "0 12 * * *"
  #       }
  #     }

  #     tags = {
  #       ExtraTag = "EKS managed node group complete example"
  #     }
  #   }
  }

  tags = local.tags
}

################################################################################
# Supporting Resources
################################################################################

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.2.0"

  name = local.name
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 48)]
  intra_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 52)]

  enable_nat_gateway     = true
  single_nat_gateway     = true
  enable_ipv6            = true
  create_egress_only_igw = true

  public_subnet_ipv6_prefixes                    = [0, 1, 2]
  public_subnet_assign_ipv6_address_on_creation  = true
  private_subnet_ipv6_prefixes                   = [3, 4, 5]
  private_subnet_assign_ipv6_address_on_creation = true
  intra_subnet_ipv6_prefixes                     = [6, 7, 8]
  intra_subnet_assign_ipv6_address_on_creation   = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }

  tags = local.tags
}

module "vpc_cni_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.32.0"

  role_name_prefix      = "VPC-CNI-IRSA"
  attach_vpc_cni_policy = true
  vpc_cni_enable_ipv6   = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-node"]
    }
  }

  tags = local.tags
}

module "ebs_kms_key" {
  source  = "terraform-aws-modules/kms/aws"
  version = "~> 2.1.0"

  description = "Customer managed key to encrypt EKS managed node group volumes"

  # Policy
  key_administrators = [
    data.aws_caller_identity.current.arn
  ]

  key_service_roles_for_autoscaling = [
    # required for the ASG to manage encrypted volumes for nodes
    "arn:${local.part}:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
    # required for the cluster / persistentvolume-controller to create encrypted PVCs
    module.eks.cluster_iam_role_arn,
  ]

  # Aliases
  aliases = ["eks/${local.name}/ebs"]

  tags = local.tags
}

module "key_pair" {
  source  = "terraform-aws-modules/key-pair/aws"
  version = "~> 2.0.2"

  key_name_prefix    = local.name
  create_private_key = true

  tags = local.tags
}

resource "aws_security_group" "remote_access" {
  name_prefix = "${local.name}-remote-access"
  description = "Allow remote SSH access"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = merge(local.tags, { Name = "${local.name}-remote" })
}

resource "aws_iam_policy" "node_additional" {
  name        = "${local.name}-additional"
  description = "Example usage of node additional policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:Describe*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })

  tags = local.tags
}

data "aws_ami" "eks_default" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amazon-eks-node-${local.cluster_version}-v*"]
  }
}

data "aws_ami" "eks_default_arm" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amazon-eks-arm64-node-${local.cluster_version}-v*"]
  }
}

data "aws_ami" "eks_default_bottlerocket" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["bottlerocket-aws-k8s-${local.cluster_version}-x86_64-*"]
  }
}

################################################################################
# Tags for the ASG to support cluster-autoscaler scale up from 0
################################################################################

locals {

  # We need to lookup K8s taint effect from the AWS API value
  taint_effects = {
    NO_SCHEDULE        = "NoSchedule"
    NO_EXECUTE         = "NoExecute"
    PREFER_NO_SCHEDULE = "PreferNoSchedule"
  }

  cluster_autoscaler_label_tags = merge([
    for name, group in module.eks.eks_managed_node_groups : {
      for label_name, label_value in coalesce(group.node_group_labels, {}) : "${name}|label|${label_name}" => {
        autoscaling_group = group.node_group_autoscaling_group_names[0],
        key               = "k8s.io/cluster-autoscaler/node-template/label/${label_name}",
        value             = label_value,
      }
    }
  ]...)

  cluster_autoscaler_taint_tags = merge([
    for name, group in module.eks.eks_managed_node_groups : {
      for taint in coalesce(group.node_group_taints, []) : "${name}|taint|${taint.key}" => {
        autoscaling_group = group.node_group_autoscaling_group_names[0],
        key               = "k8s.io/cluster-autoscaler/node-template/taint/${taint.key}"
        value             = "${taint.value}:${local.taint_effects[taint.effect]}"
      }
    }
  ]...)

  cluster_autoscaler_asg_tags = merge(local.cluster_autoscaler_label_tags, local.cluster_autoscaler_taint_tags)
}

resource "aws_autoscaling_group_tag" "cluster_autoscaler_label_tags" {
  for_each = local.cluster_autoscaler_asg_tags

  autoscaling_group_name = each.value.autoscaling_group

  tag {
    key   = each.value.key
    value = each.value.value

    propagate_at_launch = false
  }
}

## terraform show

# data.aws_ami.eks_default:
data "aws_ami" "eks_default" {
    architecture          = "x86_64"
    arn                   = "arn:aws-us-gov:ec2:us-gov-east-1::image/ami-0bb939d1f6ec46b8a"
    block_device_mappings = [
        {
            device_name  = "/dev/xvda"
            ebs          = {
                "delete_on_termination" = "true"
                "encrypted"             = "false"
                "iops"                  = "0"
                "snapshot_id"           = "snap-074289201c6cc9156"
                "throughput"            = "0"
                "volume_size"           = "20"
                "volume_type"           = "gp2"
            }
            no_device    = ""
            virtual_name = ""
        },
    ]
    creation_date         = "2023-11-16T08:14:42.000Z"
    deprecation_time      = "2025-11-16T08:14:42.000Z"
    description           = "EKS Kubernetes Worker AMI with AmazonLinux2 image, (k8s: 1.27.7, containerd: 1.6.*)"
    ena_support           = true
    hypervisor            = "xen"
    id                    = "ami-0bb939d1f6ec46b8a"
    image_id              = "ami-0bb939d1f6ec46b8a"
    image_location        = "amazon/amazon-eks-node-1.27-v20231116"
    image_owner_alias     = "amazon"
    image_type            = "machine"
    include_deprecated    = false
    most_recent           = true
    name                  = "amazon-eks-node-1.27-v20231116"
    owner_id              = "151742754352"
    owners                = [
        "amazon",
    ]
    platform_details      = "Linux/UNIX"
    product_codes         = []
    public                = true
    root_device_name      = "/dev/xvda"
    root_device_type      = "ebs"
    root_snapshot_id      = "snap-074289201c6cc9156"
    sriov_net_support     = "simple"
    state                 = "available"
    state_reason          = {
        "code"    = "UNSET"
        "message" = "UNSET"
    }
    tags                  = {}
    usage_operation       = "RunInstances"
    virtualization_type   = "hvm"

    filter {
        name   = "name"
        values = [
            "amazon-eks-node-1.27-v*",
        ]
    }
}

# data.aws_ami.eks_default_arm:
data "aws_ami" "eks_default_arm" {
    architecture          = "arm64"
    arn                   = "arn:aws-us-gov:ec2:us-gov-east-1::image/ami-07ee7c981f9527ac9"
    block_device_mappings = [
        {
            device_name  = "/dev/xvda"
            ebs          = {
                "delete_on_termination" = "true"
                "encrypted"             = "false"
                "iops"                  = "0"
                "snapshot_id"           = "snap-0a474dd42f0c03e02"
                "throughput"            = "0"
                "volume_size"           = "20"
                "volume_type"           = "gp2"
            }
            no_device    = ""
            virtual_name = ""
        },
    ]
    boot_mode             = "uefi"
    creation_date         = "2023-11-16T08:14:42.000Z"
    deprecation_time      = "2025-11-16T08:14:42.000Z"
    description           = "EKS Kubernetes Worker AMI with AmazonLinux2 image, (k8s: 1.27.7, containerd: 1.6.*)"
    ena_support           = true
    hypervisor            = "xen"
    id                    = "ami-07ee7c981f9527ac9"
    image_id              = "ami-07ee7c981f9527ac9"
    image_location        = "amazon/amazon-eks-arm64-node-1.27-v20231116"
    image_owner_alias     = "amazon"
    image_type            = "machine"
    include_deprecated    = false
    most_recent           = true
    name                  = "amazon-eks-arm64-node-1.27-v20231116"
    owner_id              = "151742754352"
    owners                = [
        "amazon",
    ]
    platform_details      = "Linux/UNIX"
    product_codes         = []
    public                = true
    root_device_name      = "/dev/xvda"
    root_device_type      = "ebs"
    root_snapshot_id      = "snap-0a474dd42f0c03e02"
    sriov_net_support     = "simple"
    state                 = "available"
    state_reason          = {
        "code"    = "UNSET"
        "message" = "UNSET"
    }
    tags                  = {}
    usage_operation       = "RunInstances"
    virtualization_type   = "hvm"

    filter {
        name   = "name"
        values = [
            "amazon-eks-arm64-node-1.27-v*",
        ]
    }
}

# data.aws_ami.eks_default_bottlerocket:
data "aws_ami" "eks_default_bottlerocket" {
    architecture          = "x86_64"
    arn                   = "arn:aws-us-gov:ec2:us-gov-east-1::image/ami-0edb2ad32c1fb83e2"
    block_device_mappings = [
        {
            device_name  = "/dev/xvda"
            ebs          = {
                "delete_on_termination" = "true"
                "encrypted"             = "false"
                "iops"                  = "0"
                "snapshot_id"           = "snap-034380d7ec373972a"
                "throughput"            = "0"
                "volume_size"           = "2"
                "volume_type"           = "gp2"
            }
            no_device    = ""
            virtual_name = ""
        },
        {
            device_name  = "/dev/xvdb"
            ebs          = {
                "delete_on_termination" = "true"
                "encrypted"             = "false"
                "iops"                  = "0"
                "snapshot_id"           = "snap-00a826e84c7d79b84"
                "throughput"            = "0"
                "volume_size"           = "20"
                "volume_type"           = "gp2"
            }
            no_device    = ""
            virtual_name = ""
        },
    ]
    creation_date         = "2023-11-10T20:48:00.000Z"
    deprecation_time      = "2025-11-10T20:48:00.000Z"
    description           = "bottlerocket-aws-k8s-1.27-x86_64-v1.16.1-763f6d4c"
    ena_support           = true
    hypervisor            = "xen"
    id                    = "ami-0edb2ad32c1fb83e2"
    image_id              = "ami-0edb2ad32c1fb83e2"
    image_location        = "amazon/bottlerocket-aws-k8s-1.27-x86_64-v1.16.1-763f6d4c"
    image_owner_alias     = "amazon"
    image_type            = "machine"
    include_deprecated    = false
    most_recent           = true
    name                  = "bottlerocket-aws-k8s-1.27-x86_64-v1.16.1-763f6d4c"
    owner_id              = "372293620468"
    owners                = [
        "amazon",
    ]
    platform_details      = "Linux/UNIX"
    product_codes         = []
    public                = true
    root_device_name      = "/dev/xvda"
    root_device_type      = "ebs"
    root_snapshot_id      = "snap-034380d7ec373972a"
    sriov_net_support     = "simple"
    state                 = "available"
    state_reason          = {
        "code"    = "UNSET"
        "message" = "UNSET"
    }
    tags                  = {}
    usage_operation       = "RunInstances"
    virtualization_type   = "hvm"

    filter {
        name   = "name"
        values = [
            "bottlerocket-aws-k8s-1.27-x86_64-*",
        ]
    }
}

# data.aws_availability_zones.available:
data "aws_availability_zones" "available" {
    group_names = [
        "us-gov-east-1",
    ]
    id          = "us-gov-east-1"
    names       = [
        "us-gov-east-1a",
        "us-gov-east-1b",
        "us-gov-east-1c",
    ]
    zone_ids    = [
        "usge1-az1",
        "usge1-az2",
        "usge1-az3",
    ]
}

# data.aws_caller_identity.current:
data "aws_caller_identity" "current" {
    account_id = "367652197469"
    arn        = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
    id         = "367652197469"
    user_id    = "AIDAVLGOHKRO624LA6FQG"
}

# data.aws_partition.current:
data "aws_partition" "current" {
    dns_suffix         = "amazonaws.com"
    id                 = "aws-us-gov"
    partition          = "aws-us-gov"
    reverse_dns_prefix = "com.amazonaws"
}

# aws_iam_policy.node_additional:
resource "aws_iam_policy" "node_additional" {
    arn         = "arn:aws-us-gov:iam::367652197469:policy/ex-stack-raw-additional"
    description = "Example usage of node additional policy"
    id          = "arn:aws-us-gov:iam::367652197469:policy/ex-stack-raw-additional"
    name        = "ex-stack-raw-additional"
    path        = "/"
    policy      = jsonencode(
        {
            Statement = [
                {
                    Action   = [
                        "ec2:Describe*",
                    ]
                    Effect   = "Allow"
                    Resource = "*"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    policy_id   = "ANPAVLGOHKRO4L3OZQDGS"
    tags        = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all    = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
}

# aws_security_group.remote_access:
resource "aws_security_group" "remote_access" {
    arn                    = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:security-group/sg-086e8ec6f75b4277c"
    description            = "Allow remote SSH access"
    egress                 = [
        {
            cidr_blocks      = [
                "0.0.0.0/0",
            ]
            description      = ""
            from_port        = 0
            ipv6_cidr_blocks = [
                "::/0",
            ]
            prefix_list_ids  = []
            protocol         = "-1"
            security_groups  = []
            self             = false
            to_port          = 0
        },
    ]
    id                     = "sg-086e8ec6f75b4277c"
    ingress                = [
        {
            cidr_blocks      = [
                "10.0.0.0/8",
            ]
            description      = "SSH access"
            from_port        = 22
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "tcp"
            security_groups  = []
            self             = false
            to_port          = 22
        },
    ]
    name                   = "ex-stack-raw-remote-access20231122195714511000000007"
    name_prefix            = "ex-stack-raw-remote-access"
    owner_id               = "367652197469"
    revoke_rules_on_delete = false
    tags                   = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-remote"
    }
    tags_all               = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-remote"
    }
    vpc_id                 = "vpc-0ce05b07909f56d75"
}


# module.ebs_kms_key.data.aws_caller_identity.current[0]:
data "aws_caller_identity" "current" {
    account_id = "367652197469"
    arn        = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
    id         = "367652197469"
    user_id    = "AIDAVLGOHKRO624LA6FQG"
}

# module.ebs_kms_key.data.aws_iam_policy_document.this[0]:
data "aws_iam_policy_document" "this" {
    id      = "2460137277"
    json    = jsonencode(
        {
            Statement = [
                {
                    Action    = "kms:*"
                    Effect    = "Allow"
                    Principal = {
                        AWS = "arn:aws-us-gov:iam::367652197469:root"
                    }
                    Resource  = "*"
                    Sid       = "Default"
                },
                {
                    Action    = [
                        "kms:Update*",
                        "kms:UntagResource",
                        "kms:TagResource",
                        "kms:ScheduleKeyDeletion",
                        "kms:Revoke*",
                        "kms:ReplicateKey",
                        "kms:Put*",
                        "kms:List*",
                        "kms:ImportKeyMaterial",
                        "kms:Get*",
                        "kms:Enable*",
                        "kms:Disable*",
                        "kms:Describe*",
                        "kms:Delete*",
                        "kms:Create*",
                        "kms:CancelKeyDeletion",
                    ]
                    Effect    = "Allow"
                    Principal = {
                        AWS = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
                    }
                    Resource  = "*"
                    Sid       = "KeyAdministration"
                },
                {
                    Action    = [
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Encrypt",
                        "kms:DescribeKey",
                        "kms:Decrypt",
                    ]
                    Effect    = "Allow"
                    Principal = {
                        AWS = [
                            "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002",
                            "arn:aws-us-gov:iam::367652197469:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                        ]
                    }
                    Resource  = "*"
                    Sid       = "KeyServiceRolesASG"
                },
                {
                    Action    = "kms:CreateGrant"
                    Condition = {
                        Bool = {
                            "kms:GrantIsForAWSResource" = "true"
                        }
                    }
                    Effect    = "Allow"
                    Principal = {
                        AWS = [
                            "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002",
                            "arn:aws-us-gov:iam::367652197469:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                        ]
                    }
                    Resource  = "*"
                    Sid       = "KeyServiceRolesASGPersistentVol"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    version = "2012-10-17"

    statement {
        actions       = [
            "kms:*",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = [
            "*",
        ]
        sid           = "Default"

        principals {
            identifiers = [
                "arn:aws-us-gov:iam::367652197469:root",
            ]
            type        = "AWS"
        }
    }
    statement {
        actions       = [
            "kms:CancelKeyDeletion",
            "kms:Create*",
            "kms:Delete*",
            "kms:Describe*",
            "kms:Disable*",
            "kms:Enable*",
            "kms:Get*",
            "kms:ImportKeyMaterial",
            "kms:List*",
            "kms:Put*",
            "kms:ReplicateKey",
            "kms:Revoke*",
            "kms:ScheduleKeyDeletion",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:Update*",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = [
            "*",
        ]
        sid           = "KeyAdministration"

        principals {
            identifiers = [
                "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io",
            ]
            type        = "AWS"
        }
    }
    statement {
        actions       = [
            "kms:Decrypt",
            "kms:DescribeKey",
            "kms:Encrypt",
            "kms:GenerateDataKey*",
            "kms:ReEncrypt*",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = [
            "*",
        ]
        sid           = "KeyServiceRolesASG"

        principals {
            identifiers = [
                "arn:aws-us-gov:iam::367652197469:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002",
            ]
            type        = "AWS"
        }
    }
    statement {
        actions       = [
            "kms:CreateGrant",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = [
            "*",
        ]
        sid           = "KeyServiceRolesASGPersistentVol"

        condition {
            test     = "Bool"
            values   = [
                "true",
            ]
            variable = "kms:GrantIsForAWSResource"
        }

        principals {
            identifiers = [
                "arn:aws-us-gov:iam::367652197469:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002",
            ]
            type        = "AWS"
        }
    }
}

# module.ebs_kms_key.data.aws_partition.current[0]:
data "aws_partition" "current" {
    dns_suffix         = "amazonaws.com"
    id                 = "aws-us-gov"
    partition          = "aws-us-gov"
    reverse_dns_prefix = "com.amazonaws"
}

# module.ebs_kms_key.aws_kms_alias.this["eks/ex-stack-raw/ebs"]:
resource "aws_kms_alias" "this" {
    arn            = "arn:aws-us-gov:kms:us-gov-east-1:367652197469:alias/eks/ex-stack-raw/ebs"
    id             = "alias/eks/ex-stack-raw/ebs"
    name           = "alias/eks/ex-stack-raw/ebs"
    target_key_arn = "arn:aws-us-gov:kms:us-gov-east-1:367652197469:key/d4e54c3c-9753-45de-8548-6d39bce17c4d"
    target_key_id  = "d4e54c3c-9753-45de-8548-6d39bce17c4d"
}

# module.ebs_kms_key.aws_kms_key.this[0]:
resource "aws_kms_key" "this" {
    arn                                = "arn:aws-us-gov:kms:us-gov-east-1:367652197469:key/d4e54c3c-9753-45de-8548-6d39bce17c4d"
    bypass_policy_lockout_safety_check = false
    customer_master_key_spec           = "SYMMETRIC_DEFAULT"
    description                        = "Customer managed key to encrypt EKS managed node group volumes"
    enable_key_rotation                = true
    id                                 = "d4e54c3c-9753-45de-8548-6d39bce17c4d"
    is_enabled                         = true
    key_id                             = "d4e54c3c-9753-45de-8548-6d39bce17c4d"
    key_usage                          = "ENCRYPT_DECRYPT"
    multi_region                       = false
    policy                             = jsonencode(
        {
            Statement = [
                {
                    Action    = "kms:*"
                    Effect    = "Allow"
                    Principal = {
                        AWS = "arn:aws-us-gov:iam::367652197469:root"
                    }
                    Resource  = "*"
                    Sid       = "Default"
                },
                {
                    Action    = [
                        "kms:Update*",
                        "kms:UntagResource",
                        "kms:TagResource",
                        "kms:ScheduleKeyDeletion",
                        "kms:Revoke*",
                        "kms:ReplicateKey",
                        "kms:Put*",
                        "kms:List*",
                        "kms:ImportKeyMaterial",
                        "kms:Get*",
                        "kms:Enable*",
                        "kms:Disable*",
                        "kms:Describe*",
                        "kms:Delete*",
                        "kms:Create*",
                        "kms:CancelKeyDeletion",
                    ]
                    Effect    = "Allow"
                    Principal = {
                        AWS = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
                    }
                    Resource  = "*"
                    Sid       = "KeyAdministration"
                },
                {
                    Action    = [
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Encrypt",
                        "kms:DescribeKey",
                        "kms:Decrypt",
                    ]
                    Effect    = "Allow"
                    Principal = {
                        AWS = [
                            "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002",
                            "arn:aws-us-gov:iam::367652197469:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                        ]
                    }
                    Resource  = "*"
                    Sid       = "KeyServiceRolesASG"
                },
                {
                    Action    = "kms:CreateGrant"
                    Condition = {
                        Bool = {
                            "kms:GrantIsForAWSResource" = "true"
                        }
                    }
                    Effect    = "Allow"
                    Principal = {
                        AWS = [
                            "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002",
                            "arn:aws-us-gov:iam::367652197469:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
                        ]
                    }
                    Resource  = "*"
                    Sid       = "KeyServiceRolesASGPersistentVol"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    tags                               = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all                           = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
}


# module.eks.data.aws_caller_identity.current:
data "aws_caller_identity" "current" {
    account_id = "367652197469"
    arn        = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
    id         = "367652197469"
    user_id    = "AIDAVLGOHKRO624LA6FQG"
}

# module.eks.data.aws_eks_addon_version.this["coredns"]:
data "aws_eks_addon_version" "this" {
    addon_name         = "coredns"
    id                 = "coredns"
    kubernetes_version = "1.27"
    most_recent        = true
    version            = "v1.10.1-eksbuild.6"
}

# module.eks.data.aws_eks_addon_version.this["kube-proxy"]:
data "aws_eks_addon_version" "this" {
    addon_name         = "kube-proxy"
    id                 = "kube-proxy"
    kubernetes_version = "1.27"
    most_recent        = true
    version            = "v1.27.6-eksbuild.2"
}

# module.eks.data.aws_eks_addon_version.this["vpc-cni"]:
data "aws_eks_addon_version" "this" {
    addon_name         = "vpc-cni"
    id                 = "vpc-cni"
    kubernetes_version = "1.27"
    most_recent        = true
    version            = "v1.15.4-eksbuild.1"
}

# module.eks.data.aws_iam_policy_document.assume_role_policy[0]:
data "aws_iam_policy_document" "assume_role_policy" {
    id      = "2764486067"
    json    = jsonencode(
        {
            Statement = [
                {
                    Action    = "sts:AssumeRole"
                    Effect    = "Allow"
                    Principal = {
                        Service = "eks.amazonaws.com"
                    }
                    Sid       = "EKSClusterAssumeRole"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    version = "2012-10-17"

    statement {
        actions       = [
            "sts:AssumeRole",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = []
        sid           = "EKSClusterAssumeRole"

        principals {
            identifiers = [
                "eks.amazonaws.com",
            ]
            type        = "Service"
        }
    }
}

# module.eks.data.aws_iam_policy_document.cni_ipv6_policy[0]:
data "aws_iam_policy_document" "cni_ipv6_policy" {
    id      = "403789187"
    json    = jsonencode(
        {
            Statement = [
                {
                    Action   = [
                        "ec2:DescribeTags",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeInstances",
                        "ec2:DescribeInstanceTypes",
                        "ec2:AssignIpv6Addresses",
                    ]
                    Effect   = "Allow"
                    Resource = "*"
                    Sid      = "AssignDescribe"
                },
                {
                    Action   = "ec2:CreateTags"
                    Effect   = "Allow"
                    Resource = "arn:aws-us-gov:ec2:*:*:network-interface/*"
                    Sid      = "CreateTags"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    version = "2012-10-17"

    statement {
        actions       = [
            "ec2:AssignIpv6Addresses",
            "ec2:DescribeInstanceTypes",
            "ec2:DescribeInstances",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeTags",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = [
            "*",
        ]
        sid           = "AssignDescribe"
    }
    statement {
        actions       = [
            "ec2:CreateTags",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = [
            "arn:aws-us-gov:ec2:*:*:network-interface/*",
        ]
        sid           = "CreateTags"
    }
}

# module.eks.data.aws_iam_session_context.current:
data "aws_iam_session_context" "current" {
    arn        = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
    id         = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
    issuer_arn = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
}

# module.eks.data.aws_partition.current:
data "aws_partition" "current" {
    dns_suffix         = "amazonaws.com"
    id                 = "aws-us-gov"
    partition          = "aws-us-gov"
    reverse_dns_prefix = "com.amazonaws"
}

# module.eks.data.tls_certificate.this[0]:
data "tls_certificate" "this" {
    certificates = [
        {
            cert_pem             = <<-EOT
                -----BEGIN CERTIFICATE-----
                MIIEdTCCA12gAwIBAgIJAKcOSkw0grd/MA0GCSqGSIb3DQEBCwUAMGgxCzAJBgNV
                BAYTAlVTMSUwIwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTIw
                MAYDVQQLEylTdGFyZmllbGQgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
                eTAeFw0wOTA5MDIwMDAwMDBaFw0zNDA2MjgxNzM5MTZaMIGYMQswCQYDVQQGEwJV
                UzEQMA4GA1UECBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTElMCMGA1UE
                ChMcU3RhcmZpZWxkIFRlY2hub2xvZ2llcywgSW5jLjE7MDkGA1UEAxMyU3RhcmZp
                ZWxkIFNlcnZpY2VzIFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwggEi
                MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVDDrEKvlO4vW+GZdfjohTsR8/
                y8+fIBNtKTrID30892t2OGPZNmCom15cAICyL1l/9of5JUOG52kbUpqQ4XHj2C0N
                Tm/2yEnZtvMaVq4rtnQU68/7JuMauh2WLmo7WJSJR1b/JaCTcFOD2oR0FMNnngRo
                Ot+OQFodSk7PQ5E751bWAHDLUu57fa4657wx+UX2wmDPE1kCK4DMNEffud6QZW0C
                zyyRpqbn3oUYSXxmTqM6bam17jQuug0DuDPfR+uxa40l2ZvOgdFFRjKWcIfeAg5J
                Q4W2bHO7ZOphQazJ1FTfhy/HIrImzJ9ZVGif/L4qL8RVHHVAYBeFAlU5i38FAgMB
                AAGjgfAwge0wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0O
                BBYEFJxfAN+qAdcwKziIorhtSpzyEZGDMB8GA1UdIwQYMBaAFL9ft9HO3R+G9FtV
                rNzXEMIOqYjnME8GCCsGAQUFBwEBBEMwQTAcBggrBgEFBQcwAYYQaHR0cDovL28u
                c3MyLnVzLzAhBggrBgEFBQcwAoYVaHR0cDovL3guc3MyLnVzL3guY2VyMCYGA1Ud
                HwQfMB0wG6AZoBeGFWh0dHA6Ly9zLnNzMi51cy9yLmNybDARBgNVHSAECjAIMAYG
                BFUdIAAwDQYJKoZIhvcNAQELBQADggEBACMd44pXyn3pF3lM8R5V/cxTbj5HD9/G
                VfKyBDbtgB9TxF00KGu+x1X8Z+rLP3+QsjPNG1gQggL4+C/1E2DUBc7xgQjB3ad1
                l08YuW3e95ORCLp+QCztweq7dp4zBncdDQh/U90bZKuCJ/Fp1U1ervShw3WnWEQt
                8jxwmKy6abaVd38PMV4s/KCHOkdp8Hlf9BRUpJVeEXgSYCfOn8J3/yNTd126/+pZ
                59vPr5KW7ySaNRB6nJHGDn2Z9j8Z3/VyVOEVqQdZe4O/Ui5GjLIAZHYcSNPYeehu
                VsyuLAOQ1xk4meTKCRlb/weWsKh/NEnfVqn3sF/tM+2MR7cwA130A4w=
                -----END CERTIFICATE-----
            EOT
            is_ca                = true
            issuer               = "OU=Starfield Class 2 Certification Authority,O=Starfield Technologies\\, Inc.,C=US"
            not_after            = "2034-06-28T17:39:16Z"
            not_before           = "2009-09-02T00:00:00Z"
            public_key_algorithm = "RSA"
            serial_number        = "12037640545166866303"
            sha1_fingerprint     = "9e99a48a9960b14926bb7f3b02e22da2b0ab7280"
            signature_algorithm  = "SHA256-RSA"
            subject              = "CN=Starfield Services Root Certificate Authority - G2,O=Starfield Technologies\\, Inc.,L=Scottsdale,ST=Arizona,C=US"
            version              = 3
        },
        {
            cert_pem             = <<-EOT
                -----BEGIN CERTIFICATE-----
                MIIEkjCCA3qgAwIBAgITBn+USionzfP6wq4rAfkI7rnExjANBgkqhkiG9w0BAQsF
                ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj
                b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x
                OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1
                dGhvcml0eSAtIEcyMB4XDTE1MDUyNTEyMDAwMFoXDTM3MTIzMTAxMDAwMFowOTEL
                MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
                b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
                ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
                9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
                IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
                VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
                93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
                jgSubJrIqg0CAwEAAaOCATEwggEtMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/
                BAQDAgGGMB0GA1UdDgQWBBSEGMyFNOy8DJSULghZnMeyEE4KCDAfBgNVHSMEGDAW
                gBScXwDfqgHXMCs4iKK4bUqc8hGRgzB4BggrBgEFBQcBAQRsMGowLgYIKwYBBQUH
                MAGGImh0dHA6Ly9vY3NwLnJvb3RnMi5hbWF6b250cnVzdC5jb20wOAYIKwYBBQUH
                MAKGLGh0dHA6Ly9jcnQucm9vdGcyLmFtYXpvbnRydXN0LmNvbS9yb290ZzIuY2Vy
                MD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6Ly9jcmwucm9vdGcyLmFtYXpvbnRydXN0
                LmNvbS9yb290ZzIuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQsF
                AAOCAQEAYjdCXLwQtT6LLOkMm2xF4gcAevnFWAu5CIw+7bMlPLVvUOTNNWqnkzSW
                MiGpSESrnO09tKpzbeR/FoCJbM8oAxiDR3mjEH4wW6w7sGDgd9QIpuEdfF7Au/ma
                eyKdpwAJfqxGF4PcnCZXmTA5YpaP7dreqsXMGz7KQ2hsVxa81Q4gLv7/wmpdLqBK
                bRRYh5TmOTFffHPLkIhqhBGWJ6bt2YFGpn6jcgAKUj6DiAdjd4lpFw85hdKrCEVN
                0FE6/V1dN2RMfjCyVSRCnTawXZwXgWHxyvkQAiSr6w10kY17RSlQOYiypok1JR4U
                akcjMS9cmvqtmg5iUaQqqcT5NJ0hGA==
                -----END CERTIFICATE-----
            EOT
            is_ca                = true
            issuer               = "CN=Starfield Services Root Certificate Authority - G2,O=Starfield Technologies\\, Inc.,L=Scottsdale,ST=Arizona,C=US"
            not_after            = "2037-12-31T01:00:00Z"
            not_before           = "2015-05-25T12:00:00Z"
            public_key_algorithm = "RSA"
            serial_number        = "144918191876577076464031512351042010504348870"
            sha1_fingerprint     = "06b25927c42a721631c1efd9431e648fa62e1e39"
            signature_algorithm  = "SHA256-RSA"
            subject              = "CN=Amazon Root CA 1,O=Amazon,C=US"
            version              = 3
        },
        {
            cert_pem             = <<-EOT
                -----BEGIN CERTIFICATE-----
                MIIEXjCCA0agAwIBAgITB3MSSkvL1E7HtTvq8ZSELToPoTANBgkqhkiG9w0BAQsF
                ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
                b24gUm9vdCBDQSAxMB4XDTIyMDgyMzIyMjUzMFoXDTMwMDgyMzIyMjUzMFowPDEL
                MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEcMBoGA1UEAxMTQW1hem9uIFJT
                QSAyMDQ4IE0wMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALtDGMZa
                qHneKei1by6+pUPPLljTB143Si6VpEWPc6mSkFhZb/6qrkZyoHlQLbDYnI2D7hD0
                sdzEqfnuAjIsuXQLG3A8TvX6V3oFNBFVe8NlLJHvBseKY88saLwufxkZVwk74g4n
                WlNMXzla9Y5F3wwRHwMVH443xGz6UtGSZSqQ94eFx5X7Tlqt8whi8qCaKdZ5rNak
                +r9nUThOeClqFd4oXych//Rc7Y0eX1KNWHYSI1Nk31mYgiK3JvH063g+K9tHA63Z
                eTgKgndlh+WI+zv7i44HepRZjA1FYwYZ9Vv/9UkC5Yz8/yU65fgjaE+wVHM4e/Yy
                C2osrPWE7gJ+dXMCAwEAAaOCAVowggFWMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYD
                VR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNV
                HQ4EFgQUwDFSzVpQw4J8dHHOy+mc+XrrguIwHwYDVR0jBBgwFoAUhBjMhTTsvAyU
                lC4IWZzHshBOCggwewYIKwYBBQUHAQEEbzBtMC8GCCsGAQUFBzABhiNodHRwOi8v
                b2NzcC5yb290Y2ExLmFtYXpvbnRydXN0LmNvbTA6BggrBgEFBQcwAoYuaHR0cDov
                L2NydC5yb290Y2ExLmFtYXpvbnRydXN0LmNvbS9yb290Y2ExLmNlcjA/BgNVHR8E
                ODA2MDSgMqAwhi5odHRwOi8vY3JsLnJvb3RjYTEuYW1hem9udHJ1c3QuY29tL3Jv
                b3RjYTEuY3JsMBMGA1UdIAQMMAowCAYGZ4EMAQIBMA0GCSqGSIb3DQEBCwUAA4IB
                AQAtTi6Fs0Azfi+iwm7jrz+CSxHH+uHl7Law3MQSXVtR8RV53PtR6r/6gNpqlzdo
                Zq4FKbADi1v9Bun8RY8D51uedRfjsbeodizeBB8nXmeyD33Ep7VATj4ozcd31YFV
                fgRhvTSxNrrTlNpWkUk0m3BMPv8sg381HhA6uEYokE5q9uws/3YkKqRiEz3TsaWm
                JqIRZhMbgAfp7O7FUwFIb7UIspogZSKxPIWJpxiPo3TcBambbVtQOcNRWz5qCQdD
                slI2yayq0n2TXoHyNCLEH8rpsJRVILFsg0jc7BaFrMnF462+ajSehgj12IidNeRN
                4zl+EoNaWdpnWndvSpAEkq2P
                -----END CERTIFICATE-----
            EOT
            is_ca                = true
            issuer               = "CN=Amazon Root CA 1,O=Amazon,C=US"
            not_after            = "2030-08-23T22:25:30Z"
            not_before           = "2022-08-23T22:25:30Z"
            public_key_algorithm = "RSA"
            serial_number        = "166129353110899469622597955040406457904926625"
            sha1_fingerprint     = "414a2060b738c635cc7fc243e052615592830c53"
            signature_algorithm  = "SHA256-RSA"
            subject              = "CN=Amazon RSA 2048 M02,O=Amazon,C=US"
            version              = 3
        },
        {
            cert_pem             = <<-EOT
                -----BEGIN CERTIFICATE-----
                MIIF9jCCBN6gAwIBAgIQDqBnMC4YeEfiyh292+cr/jANBgkqhkiG9w0BAQsFADA8
                MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRwwGgYDVQQDExNBbWF6b24g
                UlNBIDIwNDggTTAyMB4XDTIzMDIwODAwMDAwMFoXDTI0MDIwODIzNTk1OVowLzEt
                MCsGA1UEAxMkb2lkYy5la3MudXMtZ292LWVhc3QtMS5hbWF6b25hd3MuY29tMIIB
                IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnHFs56oJPGTPMCQHCn51YiF5
                FGJ4LSQg2NRou3fCKZllvzo7yyEKDLgzhnkhfbZiuZ2txtKOOaCSoO7RMKlNT8QB
                kcenbjN3L2MwzooIBtTdsd6dJkfyrJyWmB7O2B6uboECjCuiWFbIWzLwMBBMr6ok
                mm9fTFpmtE7ANPSg6yR6xgXrgTYVkLQ0DctMAbrwXT2eq4U/79fozmNszo7n5TgW
                0jVNCBhjtu3dCtERiM1Xi154g9eZpDmR8BvzsEQEH8LIADGxbRr8p6DvN2HEzD8X
                E1BgzS/zAYXOel4YgsF/CTh6yZrGG6yob+eWx+HDM8BDgbtf48QtkXmUM894UwID
                AQABo4IC/zCCAvswHwYDVR0jBBgwFoAUwDFSzVpQw4J8dHHOy+mc+XrrguIwHQYD
                VR0OBBYEFKf0/Ahe3CcnP43ng3SfpKDKHq46MC8GA1UdEQQoMCaCJG9pZGMuZWtz
                LnVzLWdvdi1lYXN0LTEuYW1hem9uYXdzLmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYD
                VR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMDsGA1UdHwQ0MDIwMKAuoCyGKmh0
                dHA6Ly9jcmwucjJtMDIuYW1hem9udHJ1c3QuY29tL3IybTAyLmNybDATBgNVHSAE
                DDAKMAgGBmeBDAECATB1BggrBgEFBQcBAQRpMGcwLQYIKwYBBQUHMAGGIWh0dHA6
                Ly9vY3NwLnIybTAyLmFtYXpvbnRydXN0LmNvbTA2BggrBgEFBQcwAoYqaHR0cDov
                L2NydC5yMm0wMi5hbWF6b250cnVzdC5jb20vcjJtMDIuY2VyMAwGA1UdEwEB/wQC
                MAAwggGABgorBgEEAdZ5AgQCBIIBcASCAWwBagB3AO7N0GTV2xrOxVy3nbTNE6Iy
                h0Z8vOzew1FIWUZxH7WbAAABhi6bEI8AAAQDAEgwRgIhAN94Rsqi1mjfB2/CdmTH
                5fJIoWHseJ/i8mSavzKjC1/XAiEAgu5xoIqWZ1OJbj7sp0qcKd4X4c0lhcx6ijT3
                ouXISL4AdwBz2Z6JG0yWeKAgfUed5rLGHNBRXnEZKoxrgBB6wXdytQAAAYYumxEB
                AAAEAwBIMEYCIQDLdwjdcNkU5GcrepqSXrm1cWZaCjtQMTf7Cu5oD0LXwAIhAIbp
                ipTfxYazWbqAZVp61LJOwj3jcFWGbg1nnDGohkmUAHYASLDja9qmRzQP5WoC+p0w
                6xxSActW3SyB2bu/qznYhHMAAAGGLpsQ+QAABAMARzBFAiADgRB0duH2qsofY67i
                IvqO4+Pk7cb5vAIWzw1iJodUggIhANAMm1rnwly/CVAMLDNr996kzhFlMV4y266e
                /UA1alEPMA0GCSqGSIb3DQEBCwUAA4IBAQAMge8ZLPB+bSxslF35gm9sBYhtHscn
                1v+cORXRQpYbkYMHU+q5AOieUSs0PzSZy5sofCBDHZgrswhVFC9o8WqUWSWe9hJT
                mKn4Ro0/4qhRnr0P2I/4rd1JVw3oYUGJiAOq+CKgjjj+b2XkO6hqlwXc/tdLBqHg
                B/ATzTpGA4GASWY8/geSeMjRNHnZ1AC6IrCSDJYsow/aE9+3Hio3mdp8oo61SJoL
                7LzEOoBheRzaXubB+4q8AUbHA0FPoMlzS+S/rjuAscGQyp5vvPq/7Y0cw00AnneJ
                09VAfM0pev/s2c7w1GoUbXseQr2GdPzsbX3M5yNXKB5jXuWGXakPi8fF
                -----END CERTIFICATE-----
            EOT
            is_ca                = false
            issuer               = "CN=Amazon RSA 2048 M02,O=Amazon,C=US"
            not_after            = "2024-02-08T23:59:59Z"
            not_before           = "2023-02-08T00:00:00Z"
            public_key_algorithm = "RSA"
            serial_number        = "19442052343761264129451354065071451134"
            sha1_fingerprint     = "d037f0ecfad6b401d71256bc3f4e4ceeaa0cfbff"
            signature_algorithm  = "SHA256-RSA"
            subject              = "CN=oidc.eks.us-gov-east-1.amazonaws.com"
            version              = 3
        },
    ]
    id           = "d48761dbb6514a6b06581f21784d48ec25fb9d9f"
    url          = "https://oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A"
    verify_chain = true
}

# module.eks.aws_cloudwatch_log_group.this[0]:
resource "aws_cloudwatch_log_group" "this" {
    arn               = "arn:aws-us-gov:logs:us-gov-east-1:367652197469:log-group:/aws/eks/ex-stack-raw/cluster"
    id                = "/aws/eks/ex-stack-raw/cluster"
    name              = "/aws/eks/ex-stack-raw/cluster"
    retention_in_days = 90
    skip_destroy      = false
    tags              = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "/aws/eks/ex-stack-raw/cluster"
    }
    tags_all          = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "/aws/eks/ex-stack-raw/cluster"
    }
}

# module.eks.aws_ec2_tag.cluster_primary_security_group["Example"]:
resource "aws_ec2_tag" "cluster_primary_security_group" {
    id          = "sg-0c44e678037562c8e,Example"
    key         = "Example"
    resource_id = "sg-0c44e678037562c8e"
    value       = "ex-stack-raw"
}

# module.eks.aws_ec2_tag.cluster_primary_security_group["GithubOrg"]:
resource "aws_ec2_tag" "cluster_primary_security_group" {
    id          = "sg-0c44e678037562c8e,GithubOrg"
    key         = "GithubOrg"
    resource_id = "sg-0c44e678037562c8e"
    value       = "terraform-aws-modules"
}

# module.eks.aws_ec2_tag.cluster_primary_security_group["GithubRepo"]:
resource "aws_ec2_tag" "cluster_primary_security_group" {
    id          = "sg-0c44e678037562c8e,GithubRepo"
    key         = "GithubRepo"
    resource_id = "sg-0c44e678037562c8e"
    value       = "terraform-aws-eks"
}

# module.eks.aws_eks_addon.before_compute["vpc-cni"]: (tainted)
resource "aws_eks_addon" "before_compute" {
    addon_name                  = "vpc-cni"
    addon_version               = "v1.15.4-eksbuild.1"
    arn                         = "arn:aws-us-gov:eks:us-gov-east-1:367652197469:addon/ex-stack-raw/vpc-cni/9ec5fc51-ce3c-4802-15ce-427b74388a6b"
    cluster_name                = "ex-stack-raw"
    configuration_values        = jsonencode(
        {
            env = {
                ENABLE_PREFIX_DELEGATION = "true"
                WARM_PREFIX_TARGET       = "1"
            }
        }
    )
    created_at                  = "2023-11-22T20:05:54Z"
    id                          = "ex-stack-raw:vpc-cni"
    modified_at                 = "2023-11-22T20:05:55Z"
    resolve_conflicts_on_update = "OVERWRITE"
    service_account_role_arn    = "arn:aws-us-gov:iam::367652197469:role/VPC-CNI-IRSA20231122200553169500000011"
    tags                        = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all                    = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }

    timeouts {}
}

# module.eks.aws_eks_cluster.this[0]:
resource "aws_eks_cluster" "this" {
    arn                       = "arn:aws-us-gov:eks:us-gov-east-1:367652197469:cluster/ex-stack-raw"
    certificate_authority     = [
        {
            data = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lJQnBLWTR3SWExdU13RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TXpFeE1qSXhPVFUzTWpaYUZ3MHpNekV4TVRreU1EQXlNalphTUJVeApFekFSQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLCkFvSUJBUUNaRzd3RE00NytpeG1hNzdkejd4MTB0YmNsSEl0eTJDc0YwWW8rQVl6cDk3d0F4eXJQbVBLK00wTTYKc0pZcXkwYXp1c2pPOG1QMGRDY3dhTWJGY3NrdXI3RTRGRXcza2xTWFdJdDlkUnJtcVRCYnFaQkIvc0NXTjZWRQpwWFR5YlFyNm85bmZiVnRLVkxwY2FqUXNTVW9YczJmRG8zbWY2T0VsMGJaLzh1UnpXZ3hiVGFwcEZTeHcyblNyCnY3R3RiTm1UYTJjVzNya0tNaUhqSkk2NVMzVnpmV1VqbFJINHVzRHVMeTFKYXpJVVFMQTdnSHBrcDFLYmN0d20KR2NVb2NBQzI2TXpGdGNXSGcvOUxWQWZwMDUvN2dRbCtSWDhBbEU3KzJPcVhhVzh2ckNpNDhubThCUkVZb1QzdQpTRldVMTUvelA1LzlhMy80WlJkWCtNbDAwTVBiQWdNQkFBR2pXVEJYTUE0R0ExVWREd0VCL3dRRUF3SUNwREFQCkJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJTRXJGbFU2eGNQaXNMVXdFN3lIZmV0NmUxdUJ6QVYKQmdOVkhSRUVEakFNZ2dwcmRXSmxjbTVsZEdWek1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQ1NZNXlrejloWgo3NHZlcTdOYnkzblhzM2lpYy82amFZQTYyZU12TEdqUlVxUlhxcmdrSWsraks0UW9sS3U5YXdzZitxRDVFVEhvCjgwaVUwZlJGVWVqQlZvdGs3UmdYbkhDQm5Kb05BNjRrR3lONmY2d0dIRFk4NklQUFI1UTBLRWpSRVplNTdXUFAKR05YMmZYYkJ3TlhFRk5lZCt2Z09JaW4yMlhkU3pMb2dDMlViQTkwMEp4Ky83ZGl3a2RMTUtKd2JZaVQ0TW5KOApQQmZlNjNtcjdpMElZbms4bnA4dDlYYnV3b3k4T0xFemU2d3pmekVRQitqRE1CcU1RL1Fpd1J0enU1U00zVUlOCjB6WSt2dVNqb2kxUVo0ODl1eTJaVithOXhpTUlUM2RFMmZFQjNvUFlYZnVhVzVMUlpVUzVoTk1vY2w4Wjg0MkQKK1crMkJsNXVad2JICi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
        },
    ]
    created_at                = "2023-11-22 19:57:49.957 +0000 UTC"
    enabled_cluster_log_types = [
        "api",
        "audit",
        "authenticator",
    ]
    endpoint                  = "https://A7DBDB5DA225547641902A877076832A.yl4.us-gov-east-1.eks.amazonaws.com"
    id                        = "ex-stack-raw"
    identity                  = [
        {
            oidc = [
                {
                    issuer = "https://oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A"
                },
            ]
        },
    ]
    name                      = "ex-stack-raw"
    platform_version          = "eks.8"
    role_arn                  = "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002"
    status                    = "ACTIVE"
    tags                      = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all                  = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    version                   = "1.27"

    encryption_config {
        resources = [
            "secrets",
        ]

        provider {
            key_arn = "arn:aws-us-gov:kms:us-gov-east-1:367652197469:key/bbc4ce6e-8a2a-4e52-8901-8667a51fdf21"
        }
    }

    kubernetes_network_config {
        ip_family         = "ipv6"
        service_ipv6_cidr = "fd47:1ab0:1102::/108"
    }

    timeouts {}

    vpc_config {
        cluster_security_group_id = "sg-0c44e678037562c8e"
        endpoint_private_access   = true
        endpoint_public_access    = true
        public_access_cidrs       = [
            "0.0.0.0/0",
        ]
        security_group_ids        = [
            "sg-068d3d2e9814c073b",
        ]
        subnet_ids                = [
            "subnet-02d37c1adeee4c033",
            "subnet-038071006d0111922",
            "subnet-0c1fd631cca57685a",
        ]
        vpc_id                    = "vpc-0ce05b07909f56d75"
    }
}

# module.eks.aws_iam_openid_connect_provider.oidc_provider[0]:
resource "aws_iam_openid_connect_provider" "oidc_provider" {
    arn             = "arn:aws-us-gov:iam::367652197469:oidc-provider/oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A"
    client_id_list  = [
        "sts.amazonaws.com",
    ]
    id              = "arn:aws-us-gov:iam::367652197469:oidc-provider/oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A"
    tags            = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-eks-irsa"
    }
    tags_all        = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-eks-irsa"
    }
    thumbprint_list = [
        "9e99a48a9960b14926bb7f3b02e22da2b0ab7280",
    ]
    url             = "oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A"
}

# module.eks.aws_iam_policy.cluster_encryption[0]:
resource "aws_iam_policy" "cluster_encryption" {
    arn         = "arn:aws-us-gov:iam::367652197469:policy/ex-stack-raw-cluster-ClusterEncryption2023112219572538890000000a"
    description = "Cluster encryption policy to allow cluster role to utilize CMK provided"
    id          = "arn:aws-us-gov:iam::367652197469:policy/ex-stack-raw-cluster-ClusterEncryption2023112219572538890000000a"
    name        = "ex-stack-raw-cluster-ClusterEncryption2023112219572538890000000a"
    name_prefix = "ex-stack-raw-cluster-ClusterEncryption"
    path        = "/"
    policy      = jsonencode(
        {
            Statement = [
                {
                    Action   = [
                        "kms:Encrypt",
                        "kms:Decrypt",
                        "kms:ListGrants",
                        "kms:DescribeKey",
                    ]
                    Effect   = "Allow"
                    Resource = "arn:aws-us-gov:kms:us-gov-east-1:367652197469:key/bbc4ce6e-8a2a-4e52-8901-8667a51fdf21"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    policy_id   = "ANPAVLGOHKROQKIQXBP7D"
    tags        = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all    = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
}

# module.eks.aws_iam_policy.cni_ipv6_policy[0]:
resource "aws_iam_policy" "cni_ipv6_policy" {
    arn         = "arn:aws-us-gov:iam::367652197469:policy/AmazonEKS_CNI_IPv6_Policy"
    description = "IAM policy for EKS CNI to assign IPV6 addresses"
    id          = "arn:aws-us-gov:iam::367652197469:policy/AmazonEKS_CNI_IPv6_Policy"
    name        = "AmazonEKS_CNI_IPv6_Policy"
    path        = "/"
    policy      = jsonencode(
        {
            Statement = [
                {
                    Action   = [
                        "ec2:DescribeTags",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeInstances",
                        "ec2:DescribeInstanceTypes",
                        "ec2:AssignIpv6Addresses",
                    ]
                    Effect   = "Allow"
                    Resource = "*"
                    Sid      = "AssignDescribe"
                },
                {
                    Action   = "ec2:CreateTags"
                    Effect   = "Allow"
                    Resource = "arn:aws-us-gov:ec2:*:*:network-interface/*"
                    Sid      = "CreateTags"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    policy_id   = "ANPAVLGOHKROQRWJ5OVRF"
    tags        = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all    = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
}

# module.eks.aws_iam_role.this[0]:
resource "aws_iam_role" "this" {
    arn                   = "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002"
    assume_role_policy    = jsonencode(
        {
            Statement = [
                {
                    Action    = "sts:AssumeRole"
                    Effect    = "Allow"
                    Principal = {
                        Service = "eks.amazonaws.com"
                    }
                    Sid       = "EKSClusterAssumeRole"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    create_date           = "2023-11-22T19:56:52Z"
    force_detach_policies = true
    id                    = "ex-stack-raw-cluster-20231122195652036200000002"
    managed_policy_arns   = [
        "arn:aws-us-gov:iam::367652197469:policy/ex-stack-raw-cluster-ClusterEncryption2023112219572538890000000a",
        "arn:aws-us-gov:iam::aws:policy/AmazonEKSClusterPolicy",
        "arn:aws-us-gov:iam::aws:policy/AmazonEKSVPCResourceController",
    ]
    max_session_duration  = 3600
    name                  = "ex-stack-raw-cluster-20231122195652036200000002"
    name_prefix           = "ex-stack-raw-cluster-"
    path                  = "/"
    tags                  = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all              = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    unique_id             = "AROAVLGOHKROQ5G34DXGZ"

    inline_policy {
        name   = "ex-stack-raw-cluster"
        policy = jsonencode(
            {
                Statement = [
                    {
                        Action   = [
                            "logs:CreateLogGroup",
                        ]
                        Effect   = "Deny"
                        Resource = "*"
                    },
                ]
                Version   = "2012-10-17"
            }
        )
    }
}

# module.eks.aws_iam_role_policy_attachment.cluster_encryption[0]:
resource "aws_iam_role_policy_attachment" "cluster_encryption" {
    id         = "ex-stack-raw-cluster-20231122195652036200000002-2023112219573477770000000b"
    policy_arn = "arn:aws-us-gov:iam::367652197469:policy/ex-stack-raw-cluster-ClusterEncryption2023112219572538890000000a"
    role       = "ex-stack-raw-cluster-20231122195652036200000002"
}

# module.eks.aws_iam_role_policy_attachment.this["AmazonEKSClusterPolicy"]:
resource "aws_iam_role_policy_attachment" "this" {
    id         = "ex-stack-raw-cluster-20231122195652036200000002-20231122195652766300000004"
    policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEKSClusterPolicy"
    role       = "ex-stack-raw-cluster-20231122195652036200000002"
}

# module.eks.aws_iam_role_policy_attachment.this["AmazonEKSVPCResourceController"]:
resource "aws_iam_role_policy_attachment" "this" {
    id         = "ex-stack-raw-cluster-20231122195652036200000002-20231122195652767400000005"
    policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEKSVPCResourceController"
    role       = "ex-stack-raw-cluster-20231122195652036200000002"
}

# module.eks.aws_security_group.cluster[0]:
resource "aws_security_group" "cluster" {
    arn                    = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:security-group/sg-068d3d2e9814c073b"
    description            = "EKS cluster security group"
    egress                 = []
    id                     = "sg-068d3d2e9814c073b"
    ingress                = [
        {
            cidr_blocks      = []
            description      = "Node groups to cluster API"
            from_port        = 443
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "tcp"
            security_groups  = [
                "sg-052fee624ec8203f4",
            ]
            self             = false
            to_port          = 443
        },
    ]
    name                   = "ex-stack-raw-cluster-20231122195716951000000009"
    name_prefix            = "ex-stack-raw-cluster-"
    owner_id               = "367652197469"
    revoke_rules_on_delete = false
    tags                   = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-cluster"
    }
    tags_all               = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-cluster"
    }
    vpc_id                 = "vpc-0ce05b07909f56d75"
}

# module.eks.aws_security_group.node[0]:
resource "aws_security_group" "node" {
    arn                    = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:security-group/sg-052fee624ec8203f4"
    description            = "EKS node shared security group"
    egress                 = [
        {
            cidr_blocks      = [
                "0.0.0.0/0",
            ]
            description      = "Allow all egress"
            from_port        = 0
            ipv6_cidr_blocks = [
                "::/0",
            ]
            prefix_list_ids  = []
            protocol         = "-1"
            security_groups  = []
            self             = false
            to_port          = 0
        },
    ]
    id                     = "sg-052fee624ec8203f4"
    ingress                = [
        {
            cidr_blocks      = []
            description      = "Cluster API to node 4443/tcp webhook"
            from_port        = 4443
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "tcp"
            security_groups  = [
                "sg-068d3d2e9814c073b",
            ]
            self             = false
            to_port          = 4443
        },
        {
            cidr_blocks      = []
            description      = "Cluster API to node 6443/tcp webhook"
            from_port        = 6443
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "tcp"
            security_groups  = [
                "sg-068d3d2e9814c073b",
            ]
            self             = false
            to_port          = 6443
        },
        {
            cidr_blocks      = []
            description      = "Cluster API to node 8443/tcp webhook"
            from_port        = 8443
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "tcp"
            security_groups  = [
                "sg-068d3d2e9814c073b",
            ]
            self             = false
            to_port          = 8443
        },
        {
            cidr_blocks      = []
            description      = "Cluster API to node 9443/tcp webhook"
            from_port        = 9443
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "tcp"
            security_groups  = [
                "sg-068d3d2e9814c073b",
            ]
            self             = false
            to_port          = 9443
        },
        {
            cidr_blocks      = []
            description      = "Cluster API to node groups"
            from_port        = 443
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "tcp"
            security_groups  = [
                "sg-068d3d2e9814c073b",
            ]
            self             = false
            to_port          = 443
        },
        {
            cidr_blocks      = []
            description      = "Cluster API to node kubelets"
            from_port        = 10250
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "tcp"
            security_groups  = [
                "sg-068d3d2e9814c073b",
            ]
            self             = false
            to_port          = 10250
        },
        {
            cidr_blocks      = []
            description      = "Node to node CoreDNS UDP"
            from_port        = 53
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "udp"
            security_groups  = []
            self             = true
            to_port          = 53
        },
        {
            cidr_blocks      = []
            description      = "Node to node CoreDNS"
            from_port        = 53
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "tcp"
            security_groups  = []
            self             = true
            to_port          = 53
        },
        {
            cidr_blocks      = []
            description      = "Node to node ingress on ephemeral ports"
            from_port        = 1025
            ipv6_cidr_blocks = []
            prefix_list_ids  = []
            protocol         = "tcp"
            security_groups  = []
            self             = true
            to_port          = 65535
        },
    ]
    name                   = "ex-stack-raw-node-20231122195714509200000006"
    name_prefix            = "ex-stack-raw-node-"
    owner_id               = "367652197469"
    revoke_rules_on_delete = false
    tags                   = {
        "Example"                            = "ex-stack-raw"
        "GithubOrg"                          = "terraform-aws-modules"
        "GithubRepo"                         = "terraform-aws-eks"
        "Name"                               = "ex-stack-raw-node"
        "kubernetes.io/cluster/ex-stack-raw" = "owned"
    }
    tags_all               = {
        "Example"                            = "ex-stack-raw"
        "GithubOrg"                          = "terraform-aws-modules"
        "GithubRepo"                         = "terraform-aws-eks"
        "Name"                               = "ex-stack-raw-node"
        "kubernetes.io/cluster/ex-stack-raw" = "owned"
    }
    vpc_id                 = "vpc-0ce05b07909f56d75"
}

# module.eks.aws_security_group_rule.cluster["ingress_nodes_443"]:
resource "aws_security_group_rule" "cluster" {
    description              = "Node groups to cluster API"
    from_port                = 443
    id                       = "sgrule-3686650903"
    protocol                 = "tcp"
    security_group_id        = "sg-068d3d2e9814c073b"
    security_group_rule_id   = "sgr-0d7b01432921d929d"
    self                     = false
    source_security_group_id = "sg-052fee624ec8203f4"
    to_port                  = 443
    type                     = "ingress"
}

# module.eks.aws_security_group_rule.node["egress_all"]:
resource "aws_security_group_rule" "node" {
    cidr_blocks       = [
        "0.0.0.0/0",
    ]
    description       = "Allow all egress"
    from_port         = 0
    id                = "sgrule-1882689886"
    ipv6_cidr_blocks  = [
        "::/0",
    ]
    prefix_list_ids   = []
    protocol          = "-1"
    security_group_id = "sg-052fee624ec8203f4"
    self              = false
    to_port           = 0
    type              = "egress"
}

# module.eks.aws_security_group_rule.node["ingress_cluster_443"]:
resource "aws_security_group_rule" "node" {
    description              = "Cluster API to node groups"
    from_port                = 443
    id                       = "sgrule-3404283193"
    prefix_list_ids          = []
    protocol                 = "tcp"
    security_group_id        = "sg-052fee624ec8203f4"
    security_group_rule_id   = "sgr-0eb939a1738a30fb1"
    self                     = false
    source_security_group_id = "sg-068d3d2e9814c073b"
    to_port                  = 443
    type                     = "ingress"
}

# module.eks.aws_security_group_rule.node["ingress_cluster_4443_webhook"]:
resource "aws_security_group_rule" "node" {
    description              = "Cluster API to node 4443/tcp webhook"
    from_port                = 4443
    id                       = "sgrule-1330845383"
    prefix_list_ids          = []
    protocol                 = "tcp"
    security_group_id        = "sg-052fee624ec8203f4"
    security_group_rule_id   = "sgr-09b5f486c364db36e"
    self                     = false
    source_security_group_id = "sg-068d3d2e9814c073b"
    to_port                  = 4443
    type                     = "ingress"
}

# module.eks.aws_security_group_rule.node["ingress_cluster_6443_webhook"]:
resource "aws_security_group_rule" "node" {
    description              = "Cluster API to node 6443/tcp webhook"
    from_port                = 6443
    id                       = "sgrule-2249290065"
    prefix_list_ids          = []
    protocol                 = "tcp"
    security_group_id        = "sg-052fee624ec8203f4"
    security_group_rule_id   = "sgr-028a2499ff646fee4"
    self                     = false
    source_security_group_id = "sg-068d3d2e9814c073b"
    to_port                  = 6443
    type                     = "ingress"
}

# module.eks.aws_security_group_rule.node["ingress_cluster_8443_webhook"]:
resource "aws_security_group_rule" "node" {
    description              = "Cluster API to node 8443/tcp webhook"
    from_port                = 8443
    id                       = "sgrule-2504871280"
    prefix_list_ids          = []
    protocol                 = "tcp"
    security_group_id        = "sg-052fee624ec8203f4"
    security_group_rule_id   = "sgr-0545e3e90f2e76678"
    self                     = false
    source_security_group_id = "sg-068d3d2e9814c073b"
    to_port                  = 8443
    type                     = "ingress"
}

# module.eks.aws_security_group_rule.node["ingress_cluster_9443_webhook"]:
resource "aws_security_group_rule" "node" {
    description              = "Cluster API to node 9443/tcp webhook"
    from_port                = 9443
    id                       = "sgrule-4058807995"
    prefix_list_ids          = []
    protocol                 = "tcp"
    security_group_id        = "sg-052fee624ec8203f4"
    security_group_rule_id   = "sgr-0a237e856f15357f8"
    self                     = false
    source_security_group_id = "sg-068d3d2e9814c073b"
    to_port                  = 9443
    type                     = "ingress"
}

# module.eks.aws_security_group_rule.node["ingress_cluster_kubelet"]:
resource "aws_security_group_rule" "node" {
    description              = "Cluster API to node kubelets"
    from_port                = 10250
    id                       = "sgrule-3535171968"
    prefix_list_ids          = []
    protocol                 = "tcp"
    security_group_id        = "sg-052fee624ec8203f4"
    security_group_rule_id   = "sgr-071404e98c4669cc7"
    self                     = false
    source_security_group_id = "sg-068d3d2e9814c073b"
    to_port                  = 10250
    type                     = "ingress"
}

# module.eks.aws_security_group_rule.node["ingress_nodes_ephemeral"]:
resource "aws_security_group_rule" "node" {
    description            = "Node to node ingress on ephemeral ports"
    from_port              = 1025
    id                     = "sgrule-3643251831"
    prefix_list_ids        = []
    protocol               = "tcp"
    security_group_id      = "sg-052fee624ec8203f4"
    security_group_rule_id = "sgr-080cfcfe7132d77eb"
    self                   = true
    to_port                = 65535
    type                   = "ingress"
}

# module.eks.aws_security_group_rule.node["ingress_self_coredns_tcp"]:
resource "aws_security_group_rule" "node" {
    description            = "Node to node CoreDNS"
    from_port              = 53
    id                     = "sgrule-2801191092"
    prefix_list_ids        = []
    protocol               = "tcp"
    security_group_id      = "sg-052fee624ec8203f4"
    security_group_rule_id = "sgr-06260b09b684cfbb7"
    self                   = true
    to_port                = 53
    type                   = "ingress"
}

# module.eks.aws_security_group_rule.node["ingress_self_coredns_udp"]:
resource "aws_security_group_rule" "node" {
    description            = "Node to node CoreDNS UDP"
    from_port              = 53
    id                     = "sgrule-44657499"
    prefix_list_ids        = []
    protocol               = "udp"
    security_group_id      = "sg-052fee624ec8203f4"
    security_group_rule_id = "sgr-09dc68c1cb1f92b5c"
    self                   = true
    to_port                = 53
    type                   = "ingress"
}

# module.eks.time_sleep.this[0]:
resource "time_sleep" "this" {
    create_duration = "30s"
    id              = "2023-11-22T20:06:22Z"
    triggers        = {
        "cluster_certificate_authority_data" = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lJQnBLWTR3SWExdU13RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TXpFeE1qSXhPVFUzTWpaYUZ3MHpNekV4TVRreU1EQXlNalphTUJVeApFekFSQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLCkFvSUJBUUNaRzd3RE00NytpeG1hNzdkejd4MTB0YmNsSEl0eTJDc0YwWW8rQVl6cDk3d0F4eXJQbVBLK00wTTYKc0pZcXkwYXp1c2pPOG1QMGRDY3dhTWJGY3NrdXI3RTRGRXcza2xTWFdJdDlkUnJtcVRCYnFaQkIvc0NXTjZWRQpwWFR5YlFyNm85bmZiVnRLVkxwY2FqUXNTVW9YczJmRG8zbWY2T0VsMGJaLzh1UnpXZ3hiVGFwcEZTeHcyblNyCnY3R3RiTm1UYTJjVzNya0tNaUhqSkk2NVMzVnpmV1VqbFJINHVzRHVMeTFKYXpJVVFMQTdnSHBrcDFLYmN0d20KR2NVb2NBQzI2TXpGdGNXSGcvOUxWQWZwMDUvN2dRbCtSWDhBbEU3KzJPcVhhVzh2ckNpNDhubThCUkVZb1QzdQpTRldVMTUvelA1LzlhMy80WlJkWCtNbDAwTVBiQWdNQkFBR2pXVEJYTUE0R0ExVWREd0VCL3dRRUF3SUNwREFQCkJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJTRXJGbFU2eGNQaXNMVXdFN3lIZmV0NmUxdUJ6QVYKQmdOVkhSRUVEakFNZ2dwcmRXSmxjbTVsZEdWek1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQ1NZNXlrejloWgo3NHZlcTdOYnkzblhzM2lpYy82amFZQTYyZU12TEdqUlVxUlhxcmdrSWsraks0UW9sS3U5YXdzZitxRDVFVEhvCjgwaVUwZlJGVWVqQlZvdGs3UmdYbkhDQm5Kb05BNjRrR3lONmY2d0dIRFk4NklQUFI1UTBLRWpSRVplNTdXUFAKR05YMmZYYkJ3TlhFRk5lZCt2Z09JaW4yMlhkU3pMb2dDMlViQTkwMEp4Ky83ZGl3a2RMTUtKd2JZaVQ0TW5KOApQQmZlNjNtcjdpMElZbms4bnA4dDlYYnV3b3k4T0xFemU2d3pmekVRQitqRE1CcU1RL1Fpd1J0enU1U00zVUlOCjB6WSt2dVNqb2kxUVo0ODl1eTJaVithOXhpTUlUM2RFMmZFQjNvUFlYZnVhVzVMUlpVUzVoTk1vY2w4Wjg0MkQKK1crMkJsNXVad2JICi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
        "cluster_endpoint"                   = "https://A7DBDB5DA225547641902A877076832A.yl4.us-gov-east-1.eks.amazonaws.com"
        "cluster_name"                       = "ex-stack-raw"
        "cluster_version"                    = "1.27"
    }
}


# module.eks.module.eks_managed_node_group["default_node_group"].data.aws_caller_identity.current:
data "aws_caller_identity" "current" {
    account_id = "367652197469"
    arn        = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
    id         = "367652197469"
    user_id    = "AIDAVLGOHKRO624LA6FQG"
}

# module.eks.module.eks_managed_node_group["default_node_group"].data.aws_iam_policy_document.assume_role_policy[0]:
data "aws_iam_policy_document" "assume_role_policy" {
    id      = "2560088296"
    json    = jsonencode(
        {
            Statement = [
                {
                    Action    = "sts:AssumeRole"
                    Effect    = "Allow"
                    Principal = {
                        Service = "ec2.amazonaws.com"
                    }
                    Sid       = "EKSNodeAssumeRole"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    version = "2012-10-17"

    statement {
        actions       = [
            "sts:AssumeRole",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = []
        sid           = "EKSNodeAssumeRole"

        principals {
            identifiers = [
                "ec2.amazonaws.com",
            ]
            type        = "Service"
        }
    }
}

# module.eks.module.eks_managed_node_group["default_node_group"].data.aws_partition.current:
data "aws_partition" "current" {
    dns_suffix         = "amazonaws.com"
    id                 = "aws-us-gov"
    partition          = "aws-us-gov"
    reverse_dns_prefix = "com.amazonaws"
}

# module.eks.module.eks_managed_node_group["default_node_group"].aws_iam_role.this[0]:
resource "aws_iam_role" "this" {
    arn                   = "arn:aws-us-gov:iam::367652197469:role/default_node_group-eks-node-group-2023112219573486330000000c"
    assume_role_policy    = jsonencode(
        {
            Statement = [
                {
                    Action    = "sts:AssumeRole"
                    Effect    = "Allow"
                    Principal = {
                        Service = "ec2.amazonaws.com"
                    }
                    Sid       = "EKSNodeAssumeRole"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    create_date           = "2023-11-22T19:57:34Z"
    description           = "EKS managed node group IAM role"
    force_detach_policies = true
    id                    = "default_node_group-eks-node-group-2023112219573486330000000c"
    managed_policy_arns   = [
        "arn:aws-us-gov:iam::367652197469:policy/AmazonEKS_CNI_IPv6_Policy",
        "arn:aws-us-gov:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
        "arn:aws-us-gov:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    ]
    max_session_duration  = 3600
    name                  = "default_node_group-eks-node-group-2023112219573486330000000c"
    name_prefix           = "default_node_group-eks-node-group-"
    path                  = "/"
    tags                  = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all              = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    unique_id             = "AROAVLGOHKROTSG7NBRGJ"
}

# module.eks.module.eks_managed_node_group["default_node_group"].aws_iam_role_policy_attachment.this["arn:aws-us-gov:iam::367652197469:policy/AmazonEKS_CNI_IPv6_Policy"]:
resource "aws_iam_role_policy_attachment" "this" {
    id         = "default_node_group-eks-node-group-2023112219573486330000000c-2023112219573557410000000f"
    policy_arn = "arn:aws-us-gov:iam::367652197469:policy/AmazonEKS_CNI_IPv6_Policy"
    role       = "default_node_group-eks-node-group-2023112219573486330000000c"
}

# module.eks.module.eks_managed_node_group["default_node_group"].aws_iam_role_policy_attachment.this["arn:aws-us-gov:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"]:
resource "aws_iam_role_policy_attachment" "this" {
    id         = "default_node_group-eks-node-group-2023112219573486330000000c-2023112219573524340000000d"
    policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
    role       = "default_node_group-eks-node-group-2023112219573486330000000c"
}

# module.eks.module.eks_managed_node_group["default_node_group"].aws_iam_role_policy_attachment.this["arn:aws-us-gov:iam::aws:policy/AmazonEKSWorkerNodePolicy"]:
resource "aws_iam_role_policy_attachment" "this" {
    id         = "default_node_group-eks-node-group-2023112219573486330000000c-2023112219573540170000000e"
    policy_arn = "arn:aws-us-gov:iam::aws:policy/AmazonEKSWorkerNodePolicy"
    role       = "default_node_group-eks-node-group-2023112219573486330000000c"
}


# module.eks.module.kms.data.aws_caller_identity.current[0]:
data "aws_caller_identity" "current" {
    account_id = "367652197469"
    arn        = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
    id         = "367652197469"
    user_id    = "AIDAVLGOHKRO624LA6FQG"
}

# module.eks.module.kms.data.aws_iam_policy_document.this[0]:
data "aws_iam_policy_document" "this" {
    id      = "2530023493"
    json    = jsonencode(
        {
            Statement = [
                {
                    Action    = [
                        "kms:Update*",
                        "kms:UntagResource",
                        "kms:TagResource",
                        "kms:ScheduleKeyDeletion",
                        "kms:Revoke*",
                        "kms:ReplicateKey",
                        "kms:Put*",
                        "kms:List*",
                        "kms:ImportKeyMaterial",
                        "kms:Get*",
                        "kms:Enable*",
                        "kms:Disable*",
                        "kms:Describe*",
                        "kms:Delete*",
                        "kms:Create*",
                        "kms:CancelKeyDeletion",
                    ]
                    Effect    = "Allow"
                    Principal = {
                        AWS = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
                    }
                    Resource  = "*"
                    Sid       = "KeyAdministration"
                },
                {
                    Action    = [
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Encrypt",
                        "kms:DescribeKey",
                        "kms:Decrypt",
                    ]
                    Effect    = "Allow"
                    Principal = {
                        AWS = "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002"
                    }
                    Resource  = "*"
                    Sid       = "KeyUsage"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    version = "2012-10-17"

    statement {
        actions       = [
            "kms:CancelKeyDeletion",
            "kms:Create*",
            "kms:Delete*",
            "kms:Describe*",
            "kms:Disable*",
            "kms:Enable*",
            "kms:Get*",
            "kms:ImportKeyMaterial",
            "kms:List*",
            "kms:Put*",
            "kms:ReplicateKey",
            "kms:Revoke*",
            "kms:ScheduleKeyDeletion",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:Update*",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = [
            "*",
        ]
        sid           = "KeyAdministration"

        principals {
            identifiers = [
                "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io",
            ]
            type        = "AWS"
        }
    }
    statement {
        actions       = [
            "kms:Decrypt",
            "kms:DescribeKey",
            "kms:Encrypt",
            "kms:GenerateDataKey*",
            "kms:ReEncrypt*",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = [
            "*",
        ]
        sid           = "KeyUsage"

        principals {
            identifiers = [
                "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002",
            ]
            type        = "AWS"
        }
    }
}

# module.eks.module.kms.data.aws_partition.current[0]:
data "aws_partition" "current" {
    dns_suffix         = "amazonaws.com"
    id                 = "aws-us-gov"
    partition          = "aws-us-gov"
    reverse_dns_prefix = "com.amazonaws"
}

# module.eks.module.kms.aws_kms_alias.this["cluster"]:
resource "aws_kms_alias" "this" {
    arn            = "arn:aws-us-gov:kms:us-gov-east-1:367652197469:alias/eks/ex-stack-raw"
    id             = "alias/eks/ex-stack-raw"
    name           = "alias/eks/ex-stack-raw"
    target_key_arn = "arn:aws-us-gov:kms:us-gov-east-1:367652197469:key/bbc4ce6e-8a2a-4e52-8901-8667a51fdf21"
    target_key_id  = "bbc4ce6e-8a2a-4e52-8901-8667a51fdf21"
}

# module.eks.module.kms.aws_kms_key.this[0]:
resource "aws_kms_key" "this" {
    arn                                = "arn:aws-us-gov:kms:us-gov-east-1:367652197469:key/bbc4ce6e-8a2a-4e52-8901-8667a51fdf21"
    bypass_policy_lockout_safety_check = false
    customer_master_key_spec           = "SYMMETRIC_DEFAULT"
    description                        = "ex-stack-raw cluster encryption key"
    enable_key_rotation                = true
    id                                 = "bbc4ce6e-8a2a-4e52-8901-8667a51fdf21"
    is_enabled                         = true
    key_id                             = "bbc4ce6e-8a2a-4e52-8901-8667a51fdf21"
    key_usage                          = "ENCRYPT_DECRYPT"
    multi_region                       = false
    policy                             = jsonencode(
        {
            Statement = [
                {
                    Action    = [
                        "kms:Update*",
                        "kms:UntagResource",
                        "kms:TagResource",
                        "kms:ScheduleKeyDeletion",
                        "kms:Revoke*",
                        "kms:ReplicateKey",
                        "kms:Put*",
                        "kms:List*",
                        "kms:ImportKeyMaterial",
                        "kms:Get*",
                        "kms:Enable*",
                        "kms:Disable*",
                        "kms:Describe*",
                        "kms:Delete*",
                        "kms:Create*",
                        "kms:CancelKeyDeletion",
                    ]
                    Effect    = "Allow"
                    Principal = {
                        AWS = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
                    }
                    Resource  = "*"
                    Sid       = "KeyAdministration"
                },
                {
                    Action    = [
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Encrypt",
                        "kms:DescribeKey",
                        "kms:Decrypt",
                    ]
                    Effect    = "Allow"
                    Principal = {
                        AWS = "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002"
                    }
                    Resource  = "*"
                    Sid       = "KeyUsage"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    tags                               = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all                           = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
}


# module.key_pair.aws_key_pair.this[0]:
resource "aws_key_pair" "this" {
    arn             = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:key-pair/ex-stack-raw20231122195652721300000003"
    fingerprint     = "ad:47:77:e8:58:27:a5:1d:70:a5:c5:3a:f8:64:8e:6c"
    id              = "ex-stack-raw20231122195652721300000003"
    key_name        = "ex-stack-raw20231122195652721300000003"
    key_name_prefix = "ex-stack-raw"
    key_pair_id     = "key-011302eb1be3489a9"
    key_type        = "rsa"
    public_key      = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDpoZxa6oRaIX4SpL8kxLszyrkex5svO9eYiZVudzgFr8rf7VP10k7DOhgAbPH+62/v8q03IIJ4yBC07lqfZXG9Vjzyikz8/+IUrIX1sOKLzm/OnuE795kEyxyHHYHBIZos2P3hI+xIBxPcd0YMDeJdEdTHzmXFbFgI4utC4okrm+Ims+X5wlCZ79RUliO0cIYEbuzuper2R88T5Rdis5P+s6c+kKiOGqVl6aMD8oozePX8krse902+4YcKeRu7Wp4xwI+kirn2z281PfCWZ+NaeDEsBUVx0nGv+L6mNhfTD0+4rDhqEw+HgADxRZ8aYCSwLVu10+7JKWoyz/FF7m3uddHb7nRgIfnszyM6saIGP34m75KcGha75rSUVbpl6P6fdm8N81iCcOul0DIFVOPckBoS7gO3CXTCkFC+UleOuMTlYoyygBeUZRpoM/j90cMVmlDmbFr88b4l7sCFpw0H5ZGUJ63ArU4kZPekJzrx3lH0mZMP07Z2nP86HmGbtbyifl3Uy5dH9r1ZvGBjUVildT4BBn/lEN3S3WvObfTDYYegWiPBOrfqeGbleOQKFoNY4SBxeuSiQSbO+gJj9QVKbn6fs2n32A+Ztg2Nvc0XkhpuzADs0vZd9sZtOtVJnnhfhVBdMjd4Slljqs/Anxh/bIakdVkigrpsI0AizhYa0w=="
    tags            = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all        = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
}

# module.key_pair.tls_private_key.this[0]:
resource "tls_private_key" "this" {
    algorithm                     = "RSA"
    ecdsa_curve                   = "P224"
    id                            = "14daf71b80210b0bbe1352033d717953d5c13341"
    private_key_openssh           = (sensitive value)
    private_key_pem               = (sensitive value)
    private_key_pem_pkcs8         = (sensitive value)
    public_key_fingerprint_md5    = "34:8e:c5:57:ec:c6:82:d1:b7:ec:bc:91:09:e8:85:30"
    public_key_fingerprint_sha256 = "SHA256:HHfSjFSfOWtaocI6ukLXwS/5XXRVb7dalxwvT1/4dyM"
    public_key_openssh            = <<-EOT
        ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDpoZxa6oRaIX4SpL8kxLszyrkex5svO9eYiZVudzgFr8rf7VP10k7DOhgAbPH+62/v8q03IIJ4yBC07lqfZXG9Vjzyikz8/+IUrIX1sOKLzm/OnuE795kEyxyHHYHBIZos2P3hI+xIBxPcd0YMDeJdEdTHzmXFbFgI4utC4okrm+Ims+X5wlCZ79RUliO0cIYEbuzuper2R88T5Rdis5P+s6c+kKiOGqVl6aMD8oozePX8krse902+4YcKeRu7Wp4xwI+kirn2z281PfCWZ+NaeDEsBUVx0nGv+L6mNhfTD0+4rDhqEw+HgADxRZ8aYCSwLVu10+7JKWoyz/FF7m3uddHb7nRgIfnszyM6saIGP34m75KcGha75rSUVbpl6P6fdm8N81iCcOul0DIFVOPckBoS7gO3CXTCkFC+UleOuMTlYoyygBeUZRpoM/j90cMVmlDmbFr88b4l7sCFpw0H5ZGUJ63ArU4kZPekJzrx3lH0mZMP07Z2nP86HmGbtbyifl3Uy5dH9r1ZvGBjUVildT4BBn/lEN3S3WvObfTDYYegWiPBOrfqeGbleOQKFoNY4SBxeuSiQSbO+gJj9QVKbn6fs2n32A+Ztg2Nvc0XkhpuzADs0vZd9sZtOtVJnnhfhVBdMjd4Slljqs/Anxh/bIakdVkigrpsI0AizhYa0w==
    EOT
    public_key_pem                = <<-EOT
        -----BEGIN PUBLIC KEY-----
        MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA6aGcWuqEWiF+EqS/JMS7
        M8q5HsebLzvXmImVbnc4Ba/K3+1T9dJOwzoYAGzx/utv7/KtNyCCeMgQtO5an2Vx
        vVY88opM/P/iFKyF9bDii85vzp7hO/eZBMschx2BwSGaLNj94SPsSAcT3HdGDA3i
        XRHUx85lxWxYCOLrQuKJK5viJrPl+cJQme/UVJYjtHCGBG7s7qXq9kfPE+UXYrOT
        /rOnPpCojhqlZemjA/KKM3j1/JK7HvdNvuGHCnkbu1qeMcCPpIq59s9vNT3wlmfj
        WngxLAVFcdJxr/i+pjYX0w9PuKw4ahMPh4AA8UWfGmAksC1btdPuySlqMs/xRe5t
        7nXR2+50YCH57M8jOrGiBj9+Ju+SnBoWu+a0lFW6Zej+n3ZvDfNYgnDrpdAyBVTj
        3JAaEu4Dtwl0wpBQvlJXjrjE5WKMsoAXlGUaaDP4/dHDFZpQ5mxa/PG+Je7AhacN
        B+WRlCetwK1OJGT3pCc68d5R9JmTD9O2dpz/Oh5hm7W8on5d1MuXR/a9WbxgY1FY
        pXU+AQZ/5RDd0t1rzm30w2GHoFojwTq36nhm5XjkChaDWOEgcXrkokEmzvoCY/UF
        Sm5+n7Np99gPmbYNjb3NF5IabswA7NL2XfbGbTrVSZ54X4VQXTI3eEpZY6rPwJ8Y
        f2yGpHVZIoK6bCNAIs4WGtMCAwEAAQ==
        -----END PUBLIC KEY-----
    EOT
    rsa_bits                      = 4096
}


# module.vpc.aws_default_network_acl.this[0]:
resource "aws_default_network_acl" "this" {
    arn                    = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:network-acl/acl-03c4c76c909359eae"
    default_network_acl_id = "acl-03c4c76c909359eae"
    id                     = "acl-03c4c76c909359eae"
    owner_id               = "367652197469"
    subnet_ids             = [
        "subnet-01ba8919439366d78",
        "subnet-02d37c1adeee4c033",
        "subnet-038071006d0111922",
        "subnet-03cae895e1c0e96af",
        "subnet-03e200d948afebf80",
        "subnet-0bcc2c5695ff63b0a",
        "subnet-0bf9ad6180e1dcb34",
        "subnet-0c1fd631cca57685a",
        "subnet-0ffcb2a2737559629",
    ]
    tags                   = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-default"
    }
    tags_all               = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-default"
    }
    vpc_id                 = "vpc-0ce05b07909f56d75"

    egress {
        action          = "allow"
        from_port       = 0
        icmp_code       = 0
        icmp_type       = 0
        ipv6_cidr_block = "::/0"
        protocol        = "-1"
        rule_no         = 101
        to_port         = 0
    }
    egress {
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        icmp_code  = 0
        icmp_type  = 0
        protocol   = "-1"
        rule_no    = 100
        to_port    = 0
    }

    ingress {
        action          = "allow"
        from_port       = 0
        icmp_code       = 0
        icmp_type       = 0
        ipv6_cidr_block = "::/0"
        protocol        = "-1"
        rule_no         = 101
        to_port         = 0
    }
    ingress {
        action     = "allow"
        cidr_block = "0.0.0.0/0"
        from_port  = 0
        icmp_code  = 0
        icmp_type  = 0
        protocol   = "-1"
        rule_no    = 100
        to_port    = 0
    }
}

# module.vpc.aws_default_route_table.default[0]:
resource "aws_default_route_table" "default" {
    arn                    = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:route-table/rtb-0a1b96f8807335463"
    default_route_table_id = "rtb-0a1b96f8807335463"
    id                     = "rtb-0a1b96f8807335463"
    owner_id               = "367652197469"
    propagating_vgws       = []
    route                  = []
    tags                   = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-default"
    }
    tags_all               = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-default"
    }
    vpc_id                 = "vpc-0ce05b07909f56d75"

    timeouts {
        create = "5m"
        update = "5m"
    }
}

# module.vpc.aws_default_security_group.this[0]:
resource "aws_default_security_group" "this" {
    arn                    = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:security-group/sg-050b5b050a4edf768"
    description            = "default VPC security group"
    egress                 = []
    id                     = "sg-050b5b050a4edf768"
    ingress                = []
    name                   = "default"
    owner_id               = "367652197469"
    revoke_rules_on_delete = false
    tags                   = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-default"
    }
    tags_all               = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-default"
    }
    vpc_id                 = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_egress_only_internet_gateway.this[0]:
resource "aws_egress_only_internet_gateway" "this" {
    id       = "eigw-0e30b69ab7710b99b"
    tags     = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw"
    }
    tags_all = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw"
    }
    vpc_id   = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_eip.nat[0]:
resource "aws_eip" "nat" {
    allocation_id        = "eipalloc-0d5cf77fc651e918c"
    association_id       = "eipassoc-06579604581660573"
    domain               = "vpc"
    id                   = "eipalloc-0d5cf77fc651e918c"
    network_border_group = "us-gov-east-1"
    network_interface    = "eni-03b6132161d1a8841"
    private_dns          = "ip-10-0-48-209.us-gov-east-1.compute.internal"
    private_ip           = "10.0.48.209"
    public_dns           = "ec2-18-254-31-6.us-gov-east-1.compute.amazonaws.com"
    public_ip            = "18.254.31.6"
    public_ipv4_pool     = "amazon"
    tags                 = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-us-gov-east-1a"
    }
    tags_all             = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-us-gov-east-1a"
    }
    vpc                  = true
}

# module.vpc.aws_internet_gateway.this[0]:
resource "aws_internet_gateway" "this" {
    arn      = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:internet-gateway/igw-0fd13fa755e45cf49"
    id       = "igw-0fd13fa755e45cf49"
    owner_id = "367652197469"
    tags     = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw"
    }
    tags_all = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw"
    }
    vpc_id   = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_nat_gateway.this[0]:
resource "aws_nat_gateway" "this" {
    allocation_id                      = "eipalloc-0d5cf77fc651e918c"
    association_id                     = "eipassoc-06579604581660573"
    connectivity_type                  = "public"
    id                                 = "nat-0384421882efcc57b"
    network_interface_id               = "eni-03b6132161d1a8841"
    private_ip                         = "10.0.48.209"
    public_ip                          = "18.254.31.6"
    secondary_allocation_ids           = []
    secondary_private_ip_address_count = 0
    secondary_private_ip_addresses     = []
    subnet_id                          = "subnet-0bcc2c5695ff63b0a"
    tags                               = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-us-gov-east-1a"
    }
    tags_all                           = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-us-gov-east-1a"
    }
}

# module.vpc.aws_route.private_dns64_nat_gateway[0]:
resource "aws_route" "private_dns64_nat_gateway" {
    destination_ipv6_cidr_block = "64:ff9b::/96"
    id                          = "r-rtb-0957626ebebe176c92696003898"
    nat_gateway_id              = "nat-0384421882efcc57b"
    origin                      = "CreateRoute"
    route_table_id              = "rtb-0957626ebebe176c9"
    state                       = "active"

    timeouts {
        create = "5m"
    }
}

# module.vpc.aws_route.private_ipv6_egress[0]:
resource "aws_route" "private_ipv6_egress" {
    destination_ipv6_cidr_block = "::/0"
    egress_only_gateway_id      = "eigw-0e30b69ab7710b99b"
    id                          = "r-rtb-0957626ebebe176c92750132062"
    origin                      = "CreateRoute"
    route_table_id              = "rtb-0957626ebebe176c9"
    state                       = "active"
}

# module.vpc.aws_route.private_ipv6_egress[1]:
resource "aws_route" "private_ipv6_egress" {
    destination_ipv6_cidr_block = "::/0"
    egress_only_gateway_id      = "eigw-0e30b69ab7710b99b"
    id                          = "r-rtb-0957626ebebe176c92750132062"
    origin                      = "CreateRoute"
    route_table_id              = "rtb-0957626ebebe176c9"
    state                       = "active"
}

# module.vpc.aws_route.private_ipv6_egress[2]:
resource "aws_route" "private_ipv6_egress" {
    destination_ipv6_cidr_block = "::/0"
    egress_only_gateway_id      = "eigw-0e30b69ab7710b99b"
    id                          = "r-rtb-0957626ebebe176c92750132062"
    origin                      = "CreateRoute"
    route_table_id              = "rtb-0957626ebebe176c9"
    state                       = "active"
}

# module.vpc.aws_route.private_nat_gateway[0]:
resource "aws_route" "private_nat_gateway" {
    destination_cidr_block = "0.0.0.0/0"
    id                     = "r-rtb-0957626ebebe176c91080289494"
    nat_gateway_id         = "nat-0384421882efcc57b"
    origin                 = "CreateRoute"
    route_table_id         = "rtb-0957626ebebe176c9"
    state                  = "active"

    timeouts {
        create = "5m"
    }
}

# module.vpc.aws_route.public_internet_gateway[0]:
resource "aws_route" "public_internet_gateway" {
    destination_cidr_block = "0.0.0.0/0"
    gateway_id             = "igw-0fd13fa755e45cf49"
    id                     = "r-rtb-0ae9d607530afc53f1080289494"
    origin                 = "CreateRoute"
    route_table_id         = "rtb-0ae9d607530afc53f"
    state                  = "active"

    timeouts {
        create = "5m"
    }
}

# module.vpc.aws_route.public_internet_gateway_ipv6[0]:
resource "aws_route" "public_internet_gateway_ipv6" {
    destination_ipv6_cidr_block = "::/0"
    gateway_id                  = "igw-0fd13fa755e45cf49"
    id                          = "r-rtb-0ae9d607530afc53f2750132062"
    origin                      = "CreateRoute"
    route_table_id              = "rtb-0ae9d607530afc53f"
    state                       = "active"
}

# module.vpc.aws_route_table.intra[0]:
resource "aws_route_table" "intra" {
    arn              = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:route-table/rtb-0eb030fe307414476"
    id               = "rtb-0eb030fe307414476"
    owner_id         = "367652197469"
    propagating_vgws = []
    route            = []
    tags             = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-intra"
    }
    tags_all         = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-intra"
    }
    vpc_id           = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_route_table.private[0]:
resource "aws_route_table" "private" {
    arn              = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:route-table/rtb-0957626ebebe176c9"
    id               = "rtb-0957626ebebe176c9"
    owner_id         = "367652197469"
    propagating_vgws = []
    route            = [
        {
            carrier_gateway_id         = ""
            cidr_block                 = ""
            core_network_arn           = ""
            destination_prefix_list_id = ""
            egress_only_gateway_id     = ""
            gateway_id                 = ""
            ipv6_cidr_block            = "64:ff9b::/96"
            local_gateway_id           = ""
            nat_gateway_id             = "nat-0384421882efcc57b"
            network_interface_id       = ""
            transit_gateway_id         = ""
            vpc_endpoint_id            = ""
            vpc_peering_connection_id  = ""
        },
        {
            carrier_gateway_id         = ""
            cidr_block                 = ""
            core_network_arn           = ""
            destination_prefix_list_id = ""
            egress_only_gateway_id     = "eigw-0e30b69ab7710b99b"
            gateway_id                 = ""
            ipv6_cidr_block            = "::/0"
            local_gateway_id           = ""
            nat_gateway_id             = ""
            network_interface_id       = ""
            transit_gateway_id         = ""
            vpc_endpoint_id            = ""
            vpc_peering_connection_id  = ""
        },
        {
            carrier_gateway_id         = ""
            cidr_block                 = "0.0.0.0/0"
            core_network_arn           = ""
            destination_prefix_list_id = ""
            egress_only_gateway_id     = ""
            gateway_id                 = ""
            ipv6_cidr_block            = ""
            local_gateway_id           = ""
            nat_gateway_id             = "nat-0384421882efcc57b"
            network_interface_id       = ""
            transit_gateway_id         = ""
            vpc_endpoint_id            = ""
            vpc_peering_connection_id  = ""
        },
    ]
    tags             = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-private"
    }
    tags_all         = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-private"
    }
    vpc_id           = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_route_table.public[0]:
resource "aws_route_table" "public" {
    arn              = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:route-table/rtb-0ae9d607530afc53f"
    id               = "rtb-0ae9d607530afc53f"
    owner_id         = "367652197469"
    propagating_vgws = []
    route            = [
        {
            carrier_gateway_id         = ""
            cidr_block                 = ""
            core_network_arn           = ""
            destination_prefix_list_id = ""
            egress_only_gateway_id     = ""
            gateway_id                 = "igw-0fd13fa755e45cf49"
            ipv6_cidr_block            = "::/0"
            local_gateway_id           = ""
            nat_gateway_id             = ""
            network_interface_id       = ""
            transit_gateway_id         = ""
            vpc_endpoint_id            = ""
            vpc_peering_connection_id  = ""
        },
        {
            carrier_gateway_id         = ""
            cidr_block                 = "0.0.0.0/0"
            core_network_arn           = ""
            destination_prefix_list_id = ""
            egress_only_gateway_id     = ""
            gateway_id                 = "igw-0fd13fa755e45cf49"
            ipv6_cidr_block            = ""
            local_gateway_id           = ""
            nat_gateway_id             = ""
            network_interface_id       = ""
            transit_gateway_id         = ""
            vpc_endpoint_id            = ""
            vpc_peering_connection_id  = ""
        },
    ]
    tags             = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-public"
    }
    tags_all         = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-public"
    }
    vpc_id           = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_route_table_association.intra[0]:
resource "aws_route_table_association" "intra" {
    id             = "rtbassoc-030a2264833580228"
    route_table_id = "rtb-0eb030fe307414476"
    subnet_id      = "subnet-0c1fd631cca57685a"
}

# module.vpc.aws_route_table_association.intra[1]:
resource "aws_route_table_association" "intra" {
    id             = "rtbassoc-05eeea39f1fb68bfa"
    route_table_id = "rtb-0eb030fe307414476"
    subnet_id      = "subnet-02d37c1adeee4c033"
}

# module.vpc.aws_route_table_association.intra[2]:
resource "aws_route_table_association" "intra" {
    id             = "rtbassoc-087f4f587310e3566"
    route_table_id = "rtb-0eb030fe307414476"
    subnet_id      = "subnet-038071006d0111922"
}

# module.vpc.aws_route_table_association.private[0]:
resource "aws_route_table_association" "private" {
    id             = "rtbassoc-07b3005d9e243a50b"
    route_table_id = "rtb-0957626ebebe176c9"
    subnet_id      = "subnet-0ffcb2a2737559629"
}

# module.vpc.aws_route_table_association.private[1]:
resource "aws_route_table_association" "private" {
    id             = "rtbassoc-0a2e834e6a83e6f5c"
    route_table_id = "rtb-0957626ebebe176c9"
    subnet_id      = "subnet-03cae895e1c0e96af"
}

# module.vpc.aws_route_table_association.private[2]:
resource "aws_route_table_association" "private" {
    id             = "rtbassoc-0c231c4c2dc50bc18"
    route_table_id = "rtb-0957626ebebe176c9"
    subnet_id      = "subnet-03e200d948afebf80"
}

# module.vpc.aws_route_table_association.public[0]:
resource "aws_route_table_association" "public" {
    id             = "rtbassoc-0080bf70bb7daaf46"
    route_table_id = "rtb-0ae9d607530afc53f"
    subnet_id      = "subnet-0bcc2c5695ff63b0a"
}

# module.vpc.aws_route_table_association.public[1]:
resource "aws_route_table_association" "public" {
    id             = "rtbassoc-0a26303b2e85d5138"
    route_table_id = "rtb-0ae9d607530afc53f"
    subnet_id      = "subnet-0bf9ad6180e1dcb34"
}

# module.vpc.aws_route_table_association.public[2]:
resource "aws_route_table_association" "public" {
    id             = "rtbassoc-03dbf0b0d729beb67"
    route_table_id = "rtb-0ae9d607530afc53f"
    subnet_id      = "subnet-01ba8919439366d78"
}

# module.vpc.aws_subnet.intra[0]:
resource "aws_subnet" "intra" {
    arn                                            = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:subnet/subnet-0c1fd631cca57685a"
    assign_ipv6_address_on_creation                = true
    availability_zone                              = "us-gov-east-1a"
    availability_zone_id                           = "usge1-az1"
    cidr_block                                     = "10.0.52.0/24"
    enable_dns64                                   = true
    enable_lni_at_device_index                     = 0
    enable_resource_name_dns_a_record_on_launch    = false
    enable_resource_name_dns_aaaa_record_on_launch = true
    id                                             = "subnet-0c1fd631cca57685a"
    ipv6_cidr_block                                = "2600:1f15:1b2:1a06::/64"
    ipv6_cidr_block_association_id                 = "subnet-cidr-assoc-0b7e5b637db10a909"
    ipv6_native                                    = false
    map_customer_owned_ip_on_launch                = false
    map_public_ip_on_launch                        = false
    owner_id                                       = "367652197469"
    private_dns_hostname_type_on_launch            = "ip-name"
    tags                                           = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-intra-us-gov-east-1a"
    }
    tags_all                                       = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-intra-us-gov-east-1a"
    }
    vpc_id                                         = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_subnet.intra[1]:
resource "aws_subnet" "intra" {
    arn                                            = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:subnet/subnet-02d37c1adeee4c033"
    assign_ipv6_address_on_creation                = true
    availability_zone                              = "us-gov-east-1b"
    availability_zone_id                           = "usge1-az2"
    cidr_block                                     = "10.0.53.0/24"
    enable_dns64                                   = true
    enable_lni_at_device_index                     = 0
    enable_resource_name_dns_a_record_on_launch    = false
    enable_resource_name_dns_aaaa_record_on_launch = true
    id                                             = "subnet-02d37c1adeee4c033"
    ipv6_cidr_block                                = "2600:1f15:1b2:1a07::/64"
    ipv6_cidr_block_association_id                 = "subnet-cidr-assoc-0e1eadd6d4fe1d611"
    ipv6_native                                    = false
    map_customer_owned_ip_on_launch                = false
    map_public_ip_on_launch                        = false
    owner_id                                       = "367652197469"
    private_dns_hostname_type_on_launch            = "ip-name"
    tags                                           = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-intra-us-gov-east-1b"
    }
    tags_all                                       = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-intra-us-gov-east-1b"
    }
    vpc_id                                         = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_subnet.intra[2]:
resource "aws_subnet" "intra" {
    arn                                            = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:subnet/subnet-038071006d0111922"
    assign_ipv6_address_on_creation                = true
    availability_zone                              = "us-gov-east-1c"
    availability_zone_id                           = "usge1-az3"
    cidr_block                                     = "10.0.54.0/24"
    enable_dns64                                   = true
    enable_lni_at_device_index                     = 0
    enable_resource_name_dns_a_record_on_launch    = false
    enable_resource_name_dns_aaaa_record_on_launch = true
    id                                             = "subnet-038071006d0111922"
    ipv6_cidr_block                                = "2600:1f15:1b2:1a08::/64"
    ipv6_cidr_block_association_id                 = "subnet-cidr-assoc-0987e140ac80bb5fc"
    ipv6_native                                    = false
    map_customer_owned_ip_on_launch                = false
    map_public_ip_on_launch                        = false
    owner_id                                       = "367652197469"
    private_dns_hostname_type_on_launch            = "ip-name"
    tags                                           = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-intra-us-gov-east-1c"
    }
    tags_all                                       = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw-intra-us-gov-east-1c"
    }
    vpc_id                                         = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_subnet.private[0]:
resource "aws_subnet" "private" {
    arn                                            = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:subnet/subnet-0ffcb2a2737559629"
    assign_ipv6_address_on_creation                = true
    availability_zone                              = "us-gov-east-1a"
    availability_zone_id                           = "usge1-az1"
    cidr_block                                     = "10.0.0.0/20"
    enable_dns64                                   = true
    enable_lni_at_device_index                     = 0
    enable_resource_name_dns_a_record_on_launch    = false
    enable_resource_name_dns_aaaa_record_on_launch = true
    id                                             = "subnet-0ffcb2a2737559629"
    ipv6_cidr_block                                = "2600:1f15:1b2:1a03::/64"
    ipv6_cidr_block_association_id                 = "subnet-cidr-assoc-0114828f831f30305"
    ipv6_native                                    = false
    map_customer_owned_ip_on_launch                = false
    map_public_ip_on_launch                        = false
    owner_id                                       = "367652197469"
    private_dns_hostname_type_on_launch            = "ip-name"
    tags                                           = {
        "Example"                         = "ex-stack-raw"
        "GithubOrg"                       = "terraform-aws-modules"
        "GithubRepo"                      = "terraform-aws-eks"
        "Name"                            = "ex-stack-raw-private-us-gov-east-1a"
        "kubernetes.io/role/internal-elb" = "1"
    }
    tags_all                                       = {
        "Example"                         = "ex-stack-raw"
        "GithubOrg"                       = "terraform-aws-modules"
        "GithubRepo"                      = "terraform-aws-eks"
        "Name"                            = "ex-stack-raw-private-us-gov-east-1a"
        "kubernetes.io/role/internal-elb" = "1"
    }
    vpc_id                                         = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_subnet.private[1]:
resource "aws_subnet" "private" {
    arn                                            = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:subnet/subnet-03cae895e1c0e96af"
    assign_ipv6_address_on_creation                = true
    availability_zone                              = "us-gov-east-1b"
    availability_zone_id                           = "usge1-az2"
    cidr_block                                     = "10.0.16.0/20"
    enable_dns64                                   = true
    enable_lni_at_device_index                     = 0
    enable_resource_name_dns_a_record_on_launch    = false
    enable_resource_name_dns_aaaa_record_on_launch = true
    id                                             = "subnet-03cae895e1c0e96af"
    ipv6_cidr_block                                = "2600:1f15:1b2:1a04::/64"
    ipv6_cidr_block_association_id                 = "subnet-cidr-assoc-0592f2978c4b28c2e"
    ipv6_native                                    = false
    map_customer_owned_ip_on_launch                = false
    map_public_ip_on_launch                        = false
    owner_id                                       = "367652197469"
    private_dns_hostname_type_on_launch            = "ip-name"
    tags                                           = {
        "Example"                         = "ex-stack-raw"
        "GithubOrg"                       = "terraform-aws-modules"
        "GithubRepo"                      = "terraform-aws-eks"
        "Name"                            = "ex-stack-raw-private-us-gov-east-1b"
        "kubernetes.io/role/internal-elb" = "1"
    }
    tags_all                                       = {
        "Example"                         = "ex-stack-raw"
        "GithubOrg"                       = "terraform-aws-modules"
        "GithubRepo"                      = "terraform-aws-eks"
        "Name"                            = "ex-stack-raw-private-us-gov-east-1b"
        "kubernetes.io/role/internal-elb" = "1"
    }
    vpc_id                                         = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_subnet.private[2]:
resource "aws_subnet" "private" {
    arn                                            = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:subnet/subnet-03e200d948afebf80"
    assign_ipv6_address_on_creation                = true
    availability_zone                              = "us-gov-east-1c"
    availability_zone_id                           = "usge1-az3"
    cidr_block                                     = "10.0.32.0/20"
    enable_dns64                                   = true
    enable_lni_at_device_index                     = 0
    enable_resource_name_dns_a_record_on_launch    = false
    enable_resource_name_dns_aaaa_record_on_launch = true
    id                                             = "subnet-03e200d948afebf80"
    ipv6_cidr_block                                = "2600:1f15:1b2:1a05::/64"
    ipv6_cidr_block_association_id                 = "subnet-cidr-assoc-066c59f2f2fb2768f"
    ipv6_native                                    = false
    map_customer_owned_ip_on_launch                = false
    map_public_ip_on_launch                        = false
    owner_id                                       = "367652197469"
    private_dns_hostname_type_on_launch            = "ip-name"
    tags                                           = {
        "Example"                         = "ex-stack-raw"
        "GithubOrg"                       = "terraform-aws-modules"
        "GithubRepo"                      = "terraform-aws-eks"
        "Name"                            = "ex-stack-raw-private-us-gov-east-1c"
        "kubernetes.io/role/internal-elb" = "1"
    }
    tags_all                                       = {
        "Example"                         = "ex-stack-raw"
        "GithubOrg"                       = "terraform-aws-modules"
        "GithubRepo"                      = "terraform-aws-eks"
        "Name"                            = "ex-stack-raw-private-us-gov-east-1c"
        "kubernetes.io/role/internal-elb" = "1"
    }
    vpc_id                                         = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_subnet.public[0]:
resource "aws_subnet" "public" {
    arn                                            = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:subnet/subnet-0bcc2c5695ff63b0a"
    assign_ipv6_address_on_creation                = true
    availability_zone                              = "us-gov-east-1a"
    availability_zone_id                           = "usge1-az1"
    cidr_block                                     = "10.0.48.0/24"
    enable_dns64                                   = true
    enable_lni_at_device_index                     = 0
    enable_resource_name_dns_a_record_on_launch    = false
    enable_resource_name_dns_aaaa_record_on_launch = true
    id                                             = "subnet-0bcc2c5695ff63b0a"
    ipv6_cidr_block                                = "2600:1f15:1b2:1a00::/64"
    ipv6_cidr_block_association_id                 = "subnet-cidr-assoc-042124be762278074"
    ipv6_native                                    = false
    map_customer_owned_ip_on_launch                = false
    map_public_ip_on_launch                        = false
    owner_id                                       = "367652197469"
    private_dns_hostname_type_on_launch            = "ip-name"
    tags                                           = {
        "Example"                = "ex-stack-raw"
        "GithubOrg"              = "terraform-aws-modules"
        "GithubRepo"             = "terraform-aws-eks"
        "Name"                   = "ex-stack-raw-public-us-gov-east-1a"
        "kubernetes.io/role/elb" = "1"
    }
    tags_all                                       = {
        "Example"                = "ex-stack-raw"
        "GithubOrg"              = "terraform-aws-modules"
        "GithubRepo"             = "terraform-aws-eks"
        "Name"                   = "ex-stack-raw-public-us-gov-east-1a"
        "kubernetes.io/role/elb" = "1"
    }
    vpc_id                                         = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_subnet.public[1]:
resource "aws_subnet" "public" {
    arn                                            = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:subnet/subnet-0bf9ad6180e1dcb34"
    assign_ipv6_address_on_creation                = true
    availability_zone                              = "us-gov-east-1b"
    availability_zone_id                           = "usge1-az2"
    cidr_block                                     = "10.0.49.0/24"
    enable_dns64                                   = true
    enable_lni_at_device_index                     = 0
    enable_resource_name_dns_a_record_on_launch    = false
    enable_resource_name_dns_aaaa_record_on_launch = true
    id                                             = "subnet-0bf9ad6180e1dcb34"
    ipv6_cidr_block                                = "2600:1f15:1b2:1a01::/64"
    ipv6_cidr_block_association_id                 = "subnet-cidr-assoc-0ef9d380a3ff0bb39"
    ipv6_native                                    = false
    map_customer_owned_ip_on_launch                = false
    map_public_ip_on_launch                        = false
    owner_id                                       = "367652197469"
    private_dns_hostname_type_on_launch            = "ip-name"
    tags                                           = {
        "Example"                = "ex-stack-raw"
        "GithubOrg"              = "terraform-aws-modules"
        "GithubRepo"             = "terraform-aws-eks"
        "Name"                   = "ex-stack-raw-public-us-gov-east-1b"
        "kubernetes.io/role/elb" = "1"
    }
    tags_all                                       = {
        "Example"                = "ex-stack-raw"
        "GithubOrg"              = "terraform-aws-modules"
        "GithubRepo"             = "terraform-aws-eks"
        "Name"                   = "ex-stack-raw-public-us-gov-east-1b"
        "kubernetes.io/role/elb" = "1"
    }
    vpc_id                                         = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_subnet.public[2]:
resource "aws_subnet" "public" {
    arn                                            = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:subnet/subnet-01ba8919439366d78"
    assign_ipv6_address_on_creation                = true
    availability_zone                              = "us-gov-east-1c"
    availability_zone_id                           = "usge1-az3"
    cidr_block                                     = "10.0.50.0/24"
    enable_dns64                                   = true
    enable_lni_at_device_index                     = 0
    enable_resource_name_dns_a_record_on_launch    = false
    enable_resource_name_dns_aaaa_record_on_launch = true
    id                                             = "subnet-01ba8919439366d78"
    ipv6_cidr_block                                = "2600:1f15:1b2:1a02::/64"
    ipv6_cidr_block_association_id                 = "subnet-cidr-assoc-0a73eb11a056967fb"
    ipv6_native                                    = false
    map_customer_owned_ip_on_launch                = false
    map_public_ip_on_launch                        = false
    owner_id                                       = "367652197469"
    private_dns_hostname_type_on_launch            = "ip-name"
    tags                                           = {
        "Example"                = "ex-stack-raw"
        "GithubOrg"              = "terraform-aws-modules"
        "GithubRepo"             = "terraform-aws-eks"
        "Name"                   = "ex-stack-raw-public-us-gov-east-1c"
        "kubernetes.io/role/elb" = "1"
    }
    tags_all                                       = {
        "Example"                = "ex-stack-raw"
        "GithubOrg"              = "terraform-aws-modules"
        "GithubRepo"             = "terraform-aws-eks"
        "Name"                   = "ex-stack-raw-public-us-gov-east-1c"
        "kubernetes.io/role/elb" = "1"
    }
    vpc_id                                         = "vpc-0ce05b07909f56d75"
}

# module.vpc.aws_vpc.this[0]:
resource "aws_vpc" "this" {
    arn                                  = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:vpc/vpc-0ce05b07909f56d75"
    assign_generated_ipv6_cidr_block     = true
    cidr_block                           = "10.0.0.0/16"
    default_network_acl_id               = "acl-03c4c76c909359eae"
    default_route_table_id               = "rtb-0a1b96f8807335463"
    default_security_group_id            = "sg-050b5b050a4edf768"
    dhcp_options_id                      = "dopt-02c4c4da8eb945dfc"
    enable_dns_hostnames                 = true
    enable_dns_support                   = true
    enable_network_address_usage_metrics = false
    id                                   = "vpc-0ce05b07909f56d75"
    instance_tenancy                     = "default"
    ipv6_association_id                  = "vpc-cidr-assoc-0018407ba6ab998d9"
    ipv6_cidr_block                      = "2600:1f15:1b2:1a00::/56"
    ipv6_cidr_block_network_border_group = "us-gov-east-1"
    ipv6_netmask_length                  = 0
    main_route_table_id                  = "rtb-0a1b96f8807335463"
    owner_id                             = "367652197469"
    tags                                 = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw"
    }
    tags_all                             = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
        "Name"       = "ex-stack-raw"
    }
}


# module.vpc_cni_irsa.data.aws_caller_identity.current:
data "aws_caller_identity" "current" {
    account_id = "367652197469"
    arn        = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
    id         = "367652197469"
    user_id    = "AIDAVLGOHKRO624LA6FQG"
}

# module.vpc_cni_irsa.data.aws_iam_policy_document.this[0]:
data "aws_iam_policy_document" "this" {
    id      = "633812534"
    json    = jsonencode(
        {
            Statement = [
                {
                    Action    = "sts:AssumeRoleWithWebIdentity"
                    Condition = {
                        StringEquals = {
                            "oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A:aud" = "sts.amazonaws.com"
                            "oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A:sub" = "system:serviceaccount:kube-system:aws-node"
                        }
                    }
                    Effect    = "Allow"
                    Principal = {
                        Federated = "arn:aws-us-gov:iam::367652197469:oidc-provider/oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A"
                    }
                },
            ]
            Version   = "2012-10-17"
        }
    )
    version = "2012-10-17"

    statement {
        actions       = [
            "sts:AssumeRoleWithWebIdentity",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = []

        condition {
            test     = "StringEquals"
            values   = [
                "sts.amazonaws.com",
            ]
            variable = "oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A:aud"
        }
        condition {
            test     = "StringEquals"
            values   = [
                "system:serviceaccount:kube-system:aws-node",
            ]
            variable = "oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A:sub"
        }

        principals {
            identifiers = [
                "arn:aws-us-gov:iam::367652197469:oidc-provider/oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A",
            ]
            type        = "Federated"
        }
    }
}

# module.vpc_cni_irsa.data.aws_iam_policy_document.vpc_cni[0]:
data "aws_iam_policy_document" "vpc_cni" {
    id      = "800294953"
    json    = jsonencode(
        {
            Statement = [
                {
                    Action   = [
                        "ec2:DescribeTags",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeInstances",
                        "ec2:DescribeInstanceTypes",
                        "ec2:AssignIpv6Addresses",
                    ]
                    Effect   = "Allow"
                    Resource = "*"
                    Sid      = "IPV6"
                },
                {
                    Action   = "ec2:CreateTags"
                    Effect   = "Allow"
                    Resource = "arn:aws-us-gov:ec2:*:*:network-interface/*"
                    Sid      = "CreateTags"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    version = "2012-10-17"

    statement {
        actions       = [
            "ec2:AssignIpv6Addresses",
            "ec2:DescribeInstanceTypes",
            "ec2:DescribeInstances",
            "ec2:DescribeNetworkInterfaces",
            "ec2:DescribeTags",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = [
            "*",
        ]
        sid           = "IPV6"
    }
    statement {
        actions       = [
            "ec2:CreateTags",
        ]
        effect        = "Allow"
        not_actions   = []
        not_resources = []
        resources     = [
            "arn:aws-us-gov:ec2:*:*:network-interface/*",
        ]
        sid           = "CreateTags"
    }
}

# module.vpc_cni_irsa.data.aws_partition.current:
data "aws_partition" "current" {
    dns_suffix         = "amazonaws.com"
    id                 = "aws-us-gov"
    partition          = "aws-us-gov"
    reverse_dns_prefix = "com.amazonaws"
}

# module.vpc_cni_irsa.data.aws_region.current:
data "aws_region" "current" {
    description = "AWS GovCloud (US-East)"
    endpoint    = "ec2.us-gov-east-1.amazonaws.com"
    id          = "us-gov-east-1"
    name        = "us-gov-east-1"
}

# module.vpc_cni_irsa.aws_iam_policy.vpc_cni[0]:
resource "aws_iam_policy" "vpc_cni" {
    arn         = "arn:aws-us-gov:iam::367652197469:policy/AmazonEKS_CNI_Policy-20231122195652035600000001"
    description = "Provides the Amazon VPC CNI Plugin (amazon-vpc-cni-k8s) the permissions it requires to modify the IPv4/IPv6 address configuration on your EKS worker nodes"
    id          = "arn:aws-us-gov:iam::367652197469:policy/AmazonEKS_CNI_Policy-20231122195652035600000001"
    name        = "AmazonEKS_CNI_Policy-20231122195652035600000001"
    name_prefix = "AmazonEKS_CNI_Policy-"
    path        = "/"
    policy      = jsonencode(
        {
            Statement = [
                {
                    Action   = [
                        "ec2:DescribeTags",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeInstances",
                        "ec2:DescribeInstanceTypes",
                        "ec2:AssignIpv6Addresses",
                    ]
                    Effect   = "Allow"
                    Resource = "*"
                    Sid      = "IPV6"
                },
                {
                    Action   = "ec2:CreateTags"
                    Effect   = "Allow"
                    Resource = "arn:aws-us-gov:ec2:*:*:network-interface/*"
                    Sid      = "CreateTags"
                },
            ]
            Version   = "2012-10-17"
        }
    )
    policy_id   = "ANPAVLGOHKROZDZYW4JNK"
    tags        = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all    = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
}

# module.vpc_cni_irsa.aws_iam_role.this[0]:
resource "aws_iam_role" "this" {
    arn                   = "arn:aws-us-gov:iam::367652197469:role/VPC-CNI-IRSA20231122200553169500000011"
    assume_role_policy    = jsonencode(
        {
            Statement = [
                {
                    Action    = "sts:AssumeRoleWithWebIdentity"
                    Condition = {
                        StringEquals = {
                            "oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A:aud" = "sts.amazonaws.com"
                            "oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A:sub" = "system:serviceaccount:kube-system:aws-node"
                        }
                    }
                    Effect    = "Allow"
                    Principal = {
                        Federated = "arn:aws-us-gov:iam::367652197469:oidc-provider/oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A"
                    }
                },
            ]
            Version   = "2012-10-17"
        }
    )
    create_date           = "2023-11-22T20:05:53Z"
    force_detach_policies = true
    id                    = "VPC-CNI-IRSA20231122200553169500000011"
    managed_policy_arns   = [
        "arn:aws-us-gov:iam::367652197469:policy/AmazonEKS_CNI_Policy-20231122195652035600000001",
    ]
    max_session_duration  = 3600
    name                  = "VPC-CNI-IRSA20231122200553169500000011"
    name_prefix           = "VPC-CNI-IRSA"
    path                  = "/"
    tags                  = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    tags_all              = {
        "Example"    = "ex-stack-raw"
        "GithubOrg"  = "terraform-aws-modules"
        "GithubRepo" = "terraform-aws-eks"
    }
    unique_id             = "AROAVLGOHKRO2N4CYGGAP"
}

# module.vpc_cni_irsa.aws_iam_role_policy_attachment.vpc_cni[0]:
resource "aws_iam_role_policy_attachment" "vpc_cni" {
    id         = "VPC-CNI-IRSA20231122200553169500000011-20231122200553516000000012"
    policy_arn = "arn:aws-us-gov:iam::367652197469:policy/AmazonEKS_CNI_Policy-20231122195652035600000001"
    role       = "VPC-CNI-IRSA20231122200553169500000011"
}


Outputs:

aws_auth_configmap_yaml = <<-EOT
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: aws-auth
      namespace: kube-system
    data:
      mapRoles: |
        - rolearn: arn:aws-us-gov:iam::367652197469:role/default_node_group-eks-node-group-2023112219573486330000000c
          username: system:node:{{EC2PrivateDNSName}}
          groups:
            - system:bootstrappers
            - system:nodes
EOT
cloudwatch_log_group_arn = "arn:aws-us-gov:logs:us-gov-east-1:367652197469:log-group:/aws/eks/ex-stack-raw/cluster"
cloudwatch_log_group_name = "/aws/eks/ex-stack-raw/cluster"
cluster_arn = "arn:aws-us-gov:eks:us-gov-east-1:367652197469:cluster/ex-stack-raw"
cluster_certificate_authority_data = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURCVENDQWUyZ0F3SUJBZ0lJQnBLWTR3SWExdU13RFFZSktvWklodmNOQVFFTEJRQXdGVEVUTUJFR0ExVUUKQXhNS2EzVmlaWEp1WlhSbGN6QWVGdzB5TXpFeE1qSXhPVFUzTWpaYUZ3MHpNekV4TVRreU1EQXlNalphTUJVeApFekFSQmdOVkJBTVRDbXQxWW1WeWJtVjBaWE13Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLCkFvSUJBUUNaRzd3RE00NytpeG1hNzdkejd4MTB0YmNsSEl0eTJDc0YwWW8rQVl6cDk3d0F4eXJQbVBLK00wTTYKc0pZcXkwYXp1c2pPOG1QMGRDY3dhTWJGY3NrdXI3RTRGRXcza2xTWFdJdDlkUnJtcVRCYnFaQkIvc0NXTjZWRQpwWFR5YlFyNm85bmZiVnRLVkxwY2FqUXNTVW9YczJmRG8zbWY2T0VsMGJaLzh1UnpXZ3hiVGFwcEZTeHcyblNyCnY3R3RiTm1UYTJjVzNya0tNaUhqSkk2NVMzVnpmV1VqbFJINHVzRHVMeTFKYXpJVVFMQTdnSHBrcDFLYmN0d20KR2NVb2NBQzI2TXpGdGNXSGcvOUxWQWZwMDUvN2dRbCtSWDhBbEU3KzJPcVhhVzh2ckNpNDhubThCUkVZb1QzdQpTRldVMTUvelA1LzlhMy80WlJkWCtNbDAwTVBiQWdNQkFBR2pXVEJYTUE0R0ExVWREd0VCL3dRRUF3SUNwREFQCkJnTlZIUk1CQWY4RUJUQURBUUgvTUIwR0ExVWREZ1FXQkJTRXJGbFU2eGNQaXNMVXdFN3lIZmV0NmUxdUJ6QVYKQmdOVkhSRUVEakFNZ2dwcmRXSmxjbTVsZEdWek1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQ1NZNXlrejloWgo3NHZlcTdOYnkzblhzM2lpYy82amFZQTYyZU12TEdqUlVxUlhxcmdrSWsraks0UW9sS3U5YXdzZitxRDVFVEhvCjgwaVUwZlJGVWVqQlZvdGs3UmdYbkhDQm5Kb05BNjRrR3lONmY2d0dIRFk4NklQUFI1UTBLRWpSRVplNTdXUFAKR05YMmZYYkJ3TlhFRk5lZCt2Z09JaW4yMlhkU3pMb2dDMlViQTkwMEp4Ky83ZGl3a2RMTUtKd2JZaVQ0TW5KOApQQmZlNjNtcjdpMElZbms4bnA4dDlYYnV3b3k4T0xFemU2d3pmekVRQitqRE1CcU1RL1Fpd1J0enU1U00zVUlOCjB6WSt2dVNqb2kxUVo0ODl1eTJaVithOXhpTUlUM2RFMmZFQjNvUFlYZnVhVzVMUlpVUzVoTk1vY2w4Wjg0MkQKK1crMkJsNXVad2JICi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
cluster_endpoint = "https://A7DBDB5DA225547641902A877076832A.yl4.us-gov-east-1.eks.amazonaws.com"
cluster_iam_role_arn = "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002"
cluster_iam_role_name = "ex-stack-raw-cluster-20231122195652036200000002"
cluster_iam_role_unique_id = "AROAVLGOHKROQ5G34DXGZ"
cluster_identity_providers = {}
cluster_name = "ex-stack-raw"
cluster_oidc_issuer_url = "https://oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A"
cluster_platform_version = "eks.8"
cluster_primary_security_group_id = "sg-0c44e678037562c8e"
cluster_security_group_arn = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:security-group/sg-068d3d2e9814c073b"
cluster_security_group_id = "sg-068d3d2e9814c073b"
cluster_status = "ACTIVE"
cluster_tls_certificate_sha1_fingerprint = "9e99a48a9960b14926bb7f3b02e22da2b0ab7280"
fargate_profiles = {}
kms_key_arn = "arn:aws-us-gov:kms:us-gov-east-1:367652197469:key/bbc4ce6e-8a2a-4e52-8901-8667a51fdf21"
kms_key_id = "bbc4ce6e-8a2a-4e52-8901-8667a51fdf21"
kms_key_policy = jsonencode(
    {
        Statement = [
            {
                Action    = [
                    "kms:Update*",
                    "kms:UntagResource",
                    "kms:TagResource",
                    "kms:ScheduleKeyDeletion",
                    "kms:Revoke*",
                    "kms:ReplicateKey",
                    "kms:Put*",
                    "kms:List*",
                    "kms:ImportKeyMaterial",
                    "kms:Get*",
                    "kms:Enable*",
                    "kms:Disable*",
                    "kms:Describe*",
                    "kms:Delete*",
                    "kms:Create*",
                    "kms:CancelKeyDeletion",
                ]
                Effect    = "Allow"
                Principal = {
                    AWS = "arn:aws-us-gov:iam::367652197469:user/tthomas@vivsoft.io"
                }
                Resource  = "*"
                Sid       = "KeyAdministration"
            },
            {
                Action    = [
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:Encrypt",
                    "kms:DescribeKey",
                    "kms:Decrypt",
                ]
                Effect    = "Allow"
                Principal = {
                    AWS = "arn:aws-us-gov:iam::367652197469:role/ex-stack-raw-cluster-20231122195652036200000002"
                }
                Resource  = "*"
                Sid       = "KeyUsage"
            },
        ]
        Version   = "2012-10-17"
    }
)
node_security_group_arn = "arn:aws-us-gov:ec2:us-gov-east-1:367652197469:security-group/sg-052fee624ec8203f4"
node_security_group_id = "sg-052fee624ec8203f4"
oidc_provider = "oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A"
oidc_provider_arn = "arn:aws-us-gov:iam::367652197469:oidc-provider/oidc.eks.us-gov-east-1.amazonaws.com/id/A7DBDB5DA225547641902A877076832A"
self_managed_node_groups = {}
self_managed_node_groups_autoscaling_group_names = []
