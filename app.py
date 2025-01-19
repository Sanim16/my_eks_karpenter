#!/usr/bin/env python3

import aws_cdk as cdk

from my_eks_karpenter.my_eks_karpenter_stack import MyEksKarpenterStack


app = cdk.App()
MyEksKarpenterStack(app, "MyEksKarpenterStack")

app.synth()
