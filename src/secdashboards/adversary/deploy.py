"""Deployment utilities for adversary testing Lambda.

This module provides tools to deploy the network adversary testing Lambda
function to AWS. The Lambda can be deployed in a VPC to generate network
traffic that triggers security detections.
"""

import shutil
import zipfile
from pathlib import Path
from typing import Any

import boto3
import yaml


class AdversaryLambdaBuilder:
    """Builder for adversary testing Lambda deployment packages."""

    def __init__(self, output_dir: Path | str) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._lambda_client = None

    @property
    def lambda_client(self) -> Any:
        if not self._lambda_client:
            self._lambda_client = boto3.client("lambda")
        return self._lambda_client

    def build_package(self) -> Path:
        """Build the Lambda deployment package.

        Returns:
            Path to the created zip file
        """
        package_dir = self.output_dir / "adversary_lambda_package"
        package_dir.mkdir(exist_ok=True)

        # Copy the handler
        handler_src = Path(__file__).parent / "lambda_handler.py"
        handler_dst = package_dir / "lambda_handler.py"

        if handler_src.exists():
            shutil.copy(handler_src, handler_dst)
        else:
            # If running from installed package, write the handler directly
            self._write_embedded_handler(handler_dst)

        # Create zip
        zip_path = self.output_dir / "adversary_network_tester.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file_path in package_dir.rglob("*"):
                if file_path.is_file():
                    arcname = file_path.relative_to(package_dir)
                    zf.write(file_path, arcname)

        return zip_path

    def _write_embedded_handler(self, path: Path) -> None:
        """Write the handler if source file is not available."""
        # Read from the module's lambda_handler
        import inspect

        from secdashboards.adversary import lambda_handler

        source = inspect.getsource(lambda_handler)
        path.write_text(source)

    def deploy(
        self,
        function_name: str = "secdash-adversary-network-tester",
        role_arn: str | None = None,
        vpc_config: dict[str, Any] | None = None,
        environment: dict[str, str] | None = None,
        memory_mb: int = 128,
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        """Deploy the adversary Lambda function.

        Args:
            function_name: Name for the Lambda function
            role_arn: IAM role ARN for the Lambda
            vpc_config: VPC configuration for network access
            environment: Environment variables
            memory_mb: Memory allocation
            timeout_seconds: Timeout setting

        Returns:
            Deployment result with function ARN
        """
        if not role_arn:
            raise ValueError("role_arn is required for deployment")

        package_path = self.build_package()

        env_vars = {
            "DEFAULT_TARGET_IP": "127.0.0.1",
            "DNS_SERVER": "8.8.8.8",
        }
        if environment:
            env_vars.update(environment)

        with package_path.open("rb") as f:
            zip_content = f.read()

        function_config = {
            "FunctionName": function_name,
            "Runtime": "python3.12",
            "Role": role_arn,
            "Handler": "lambda_handler.handler",
            "Code": {"ZipFile": zip_content},
            "MemorySize": memory_mb,
            "Timeout": timeout_seconds,
            "Environment": {"Variables": env_vars},
            "Tags": {
                "Application": "secdashboards",
                "Purpose": "adversary-testing",
            },
        }

        if vpc_config:
            function_config["VpcConfig"] = vpc_config

        try:
            # Try to update existing function
            self.lambda_client.update_function_code(
                FunctionName=function_name,
                ZipFile=zip_content,
            )
            self.lambda_client.update_function_configuration(
                FunctionName=function_name,
                Runtime="python3.12",
                Handler="lambda_handler.handler",
                MemorySize=memory_mb,
                Timeout=timeout_seconds,
                Environment={"Variables": env_vars},
                VpcConfig=vpc_config or {},
            )
            response = self.lambda_client.get_function(FunctionName=function_name)
            return {
                "function_name": function_name,
                "function_arn": response["Configuration"]["FunctionArn"],
                "action": "updated",
            }

        except self.lambda_client.exceptions.ResourceNotFoundException:
            # Create new function
            response = self.lambda_client.create_function(**function_config)
            return {
                "function_name": function_name,
                "function_arn": response["FunctionArn"],
                "action": "created",
            }

    def generate_cloudformation_template(
        self,
        vpc_id: str | None = None,
        subnet_ids: list[str] | None = None,
        security_group_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Generate CloudFormation template for adversary Lambda.

        Args:
            vpc_id: Optional VPC ID for network deployment
            subnet_ids: Subnet IDs for VPC deployment
            security_group_ids: Security group IDs for VPC deployment

        Returns:
            CloudFormation template as dictionary
        """
        template: dict[str, Any] = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "Adversary Network Testing Lambda - secdashboards",
            "Parameters": {
                "DefaultTargetIP": {
                    "Type": "String",
                    "Default": "127.0.0.1",
                    "Description": "Default target IP for tests",
                },
                "DNSServer": {
                    "Type": "String",
                    "Default": "8.8.8.8",
                    "Description": "DNS server for queries",
                },
            },
            "Resources": {
                # IAM Role
                "AdversaryLambdaRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": "secdash-adversary-lambda-role",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                        ],
                    },
                },
                # Lambda Function
                "AdversaryNetworkTester": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "FunctionName": "secdash-adversary-network-tester",
                        "Runtime": "python3.12",
                        "Handler": "lambda_handler.handler",
                        "Role": {"Fn::GetAtt": ["AdversaryLambdaRole", "Arn"]},
                        "Code": {
                            "ZipFile": "# Placeholder - deploy actual code via update",
                        },
                        "MemorySize": 128,
                        "Timeout": 60,
                        "Environment": {
                            "Variables": {
                                "DEFAULT_TARGET_IP": {"Ref": "DefaultTargetIP"},
                                "DNS_SERVER": {"Ref": "DNSServer"},
                            }
                        },
                        "Tags": [
                            {"Key": "Application", "Value": "secdashboards"},
                            {"Key": "Purpose", "Value": "adversary-testing"},
                        ],
                    },
                },
            },
            "Outputs": {
                "FunctionArn": {
                    "Description": "Adversary Lambda Function ARN",
                    "Value": {"Fn::GetAtt": ["AdversaryNetworkTester", "Arn"]},
                    "Export": {"Name": "secdash-adversary-lambda-arn"},
                },
                "FunctionName": {
                    "Description": "Adversary Lambda Function Name",
                    "Value": {"Ref": "AdversaryNetworkTester"},
                },
            },
        }

        # Add VPC configuration if provided
        if vpc_id and subnet_ids and security_group_ids:
            template["Parameters"]["VpcId"] = {
                "Type": "AWS::EC2::VPC::Id",
                "Default": vpc_id,
                "Description": "VPC for Lambda deployment",
            }
            template["Parameters"]["SubnetIds"] = {
                "Type": "List<AWS::EC2::Subnet::Id>",
                "Default": ",".join(subnet_ids),
                "Description": "Subnets for Lambda",
            }
            template["Parameters"]["SecurityGroupIds"] = {
                "Type": "List<AWS::EC2::SecurityGroup::Id>",
                "Default": ",".join(security_group_ids),
                "Description": "Security groups for Lambda",
            }

            # Add VPC execution role
            template["Resources"]["AdversaryLambdaRole"]["Properties"]["ManagedPolicyArns"].append(
                "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
            )

            # Add VPC config to Lambda
            template["Resources"]["AdversaryNetworkTester"]["Properties"]["VpcConfig"] = {
                "SubnetIds": {"Ref": "SubnetIds"},
                "SecurityGroupIds": {"Ref": "SecurityGroupIds"},
            }

        return template

    def generate_sam_template(
        self,
        include_api_gateway: bool = False,
        include_schedule: bool = False,
        schedule_expression: str = "rate(1 hour)",
    ) -> dict[str, Any]:
        """Generate SAM template for adversary Lambda.

        Args:
            include_api_gateway: Add API Gateway trigger
            include_schedule: Add scheduled execution
            schedule_expression: CloudWatch schedule expression

        Returns:
            SAM template as dictionary
        """
        template: dict[str, Any] = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Transform": "AWS::Serverless-2016-10-31",
            "Description": "Adversary Network Testing Lambda - secdashboards (SAM)",
            "Globals": {
                "Function": {
                    "Timeout": 60,
                    "MemorySize": 128,
                }
            },
            "Parameters": {
                "DefaultTargetIP": {
                    "Type": "String",
                    "Default": "127.0.0.1",
                },
                "DNSServer": {
                    "Type": "String",
                    "Default": "8.8.8.8",
                },
            },
            "Resources": {
                "AdversaryNetworkTester": {
                    "Type": "AWS::Serverless::Function",
                    "Properties": {
                        "FunctionName": "secdash-adversary-network-tester",
                        "CodeUri": "./adversary_lambda_package/",
                        "Handler": "lambda_handler.handler",
                        "Runtime": "python3.12",
                        "Environment": {
                            "Variables": {
                                "DEFAULT_TARGET_IP": {"Ref": "DefaultTargetIP"},
                                "DNS_SERVER": {"Ref": "DNSServer"},
                            }
                        },
                        "Tags": {
                            "Application": "secdashboards",
                            "Purpose": "adversary-testing",
                        },
                        "Events": {},
                    },
                },
            },
            "Outputs": {
                "FunctionArn": {
                    "Description": "Adversary Lambda Function ARN",
                    "Value": {"Fn::GetAtt": ["AdversaryNetworkTester", "Arn"]},
                },
            },
        }

        events = template["Resources"]["AdversaryNetworkTester"]["Properties"]["Events"]

        if include_api_gateway:
            events["ApiEvent"] = {
                "Type": "Api",
                "Properties": {
                    "Path": "/test",
                    "Method": "post",
                },
            }
            template["Outputs"]["ApiEndpoint"] = {
                "Description": "API Gateway endpoint URL",
                "Value": {
                    "Fn::Sub": "https://${ServerlessRestApi}.execute-api.${AWS::Region}.amazonaws.com/Prod/test"
                },
            }

        if include_schedule:
            events["ScheduleEvent"] = {
                "Type": "Schedule",
                "Properties": {
                    "Schedule": schedule_expression,
                    "Description": "Periodic adversary test execution",
                },
            }

        return template

    def write_template(
        self,
        template: dict[str, Any],
        output_path: Path | str,
    ) -> None:
        """Write template to YAML file."""
        output_path = Path(output_path)
        with output_path.open("w") as f:
            yaml.dump(template, f, default_flow_style=False, sort_keys=False)

    def invoke_test(
        self,
        function_name: str = "secdash-adversary-network-tester",
        scenario: str | None = None,
        tests: list[dict[str, Any]] | None = None,
        target_ip: str | None = None,
    ) -> dict[str, Any]:
        """Invoke the adversary Lambda for testing.

        Args:
            function_name: Name of the deployed function
            scenario: Pre-defined scenario to run
            tests: Custom tests to run
            target_ip: Override target IP

        Returns:
            Lambda invocation result
        """
        import json

        payload: dict[str, Any] = {}

        if scenario:
            payload["scenario"] = scenario
        if tests:
            payload["tests"] = tests
        if target_ip:
            payload["target_ip"] = target_ip

        response = self.lambda_client.invoke(
            FunctionName=function_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(payload),
        )

        response_payload = json.loads(response["Payload"].read())
        return response_payload

    def list_scenarios(
        self,
        function_name: str = "secdash-adversary-network-tester",
    ) -> dict[str, Any]:
        """List available test scenarios from deployed Lambda."""
        return self.invoke_test(
            function_name=function_name,
            tests=[{"type": "list_scenarios"}],  # This will trigger listing
        )


def create_deployment_package(output_dir: str = "./build") -> Path:
    """Convenience function to create deployment package.

    Args:
        output_dir: Directory to write package

    Returns:
        Path to zip file
    """
    builder = AdversaryLambdaBuilder(output_dir)
    return builder.build_package()
