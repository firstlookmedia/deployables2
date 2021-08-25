#!/usr/bin/env python3
import sys
import os
import subprocess
import datetime
import base64
import json
import time

import click
import boto3
import jinja2


class Deployables2:
    def __init__(self):
        self._load_vars_from_env(
            [
                ("AWS_ACCESS_KEY_ID", None),
                ("AWS_SECRET_ACCESS_KEY", None),
                ("DEPLOY_ADD_ENV_TO_TAG", None),
                ("DEPLOY_APP_NAME", None),
                ("DEPLOY_AWS_ACCOUNT", None),
                ("DEPLOY_AWS_REGION", "us-east-1"),
                ("DEPLOY_AWS_ROLE", "ops-admin"),
                ("DEPLOY_DOCKER_LOCAL_TAG", os.environ.get("DEPLOY_APP_NAME")),
                ("DEPLOY_ECR_ACCOUNT", None),
                ("DEPLOY_ECS_FARGATE", False),
                ("DEPLOY_ECS_FARGATE_CPU", "256"),
                ("DEPLOY_ECS_FARGATE_MEMORY", "512"),
                ("DEPLOY_ECS_FARGATE_EXECUTION_ROLE_NAME", None),
                ("DEPLOY_ECS_FARGATE_TASK_ROLE_NAME", None),
                ("DEPLOY_ECR_HOST", None),
                ("DEPLOY_ECS_CLUSTER_NAME", None),
                ("DEPLOY_ECS_SUBFAMILY", None),
                ("DEPLOY_ENV_TO_TAG", None),
                ("DEPLOY_GITHUB_MACHINE_USER_KEY_FINGERPRINT", None),
                ("DEPLOY_TASK_DEF_TEMPLATE", None),
                ("DEPLOY_SHA1", None),
                ("FLM_ENV", None),
                ("NPM_TOKEN", None),
                # For task def templates
                ("TASK_MEMORY", os.environ.get("DEPLOY_ECS_FARGATE_MEMORY", "512")),
                ("BASIC_AUTH_PASS", ""),
                ("BASIC_AUTH_USER", ""),
                ("DEBUG_TRACKING", ""),
                ("FALCON_ORIGIN", ""),
                ("FB_PIXEL_ID", ""),
                ("GA_ID", ""),
                ("CIRCLE_BRANCH", ""),
                ("CIRCLE_SHA1", ""),
                ("CIRCLE_TAG", ""),
                ("GRAPHQL_ORIGIN", ""),
                ("GTM_AUTH", ""),
                ("GTM_PREVIEW", ""),
                ("GTM", ""),
                ("ORIGIN", ""),
                ("PARSELY_ID", ""),
                ("REDIRECT_WWW", ""),
                ("SENTRY_DSN", ""),
                ("SERVER_TYPE", ""),
                ("SHOW_ERRORS", ""),
                ("TURNSTILE_ORIGIN", ""),
                ("PERSIST_QUERIES", ""),
                ("STATIC_QUERY_SUFFIX", ""),
                ("PREVIEW_TURNSTILE_AUTH_TOKEN", ""),
                ("FIRSTLOOKMEDIA_ORIGIN", ""),
            ]
        )

        self.current_date = datetime.datetime.now().strftime("%Y%m%d")

    def docker_build(self):
        click.echo("Building docker image")
        if not self._required_env(["DEPLOY_DOCKER_LOCAL_TAG"]):
            return

        self._display_vars(
            [
                "DEPLOY_DOCKER_LOCAL_TAG",
                "DEPLOY_GITHUB_MACHINE_USER_KEY_FINGERPRINT",
            ]
        )

        if self.vars["DEPLOY_GITHUB_MACHINE_USER_KEY_FINGERPRINT"]:
            fingerprint = self.vars[
                "DEPLOY_GITHUB_MACHINE_USER_KEY_FINGERPRINT"
            ].replace(":", "")
            keyfile = os.path.expanduser(f"~/.ssh/id_{fingerprint}")

            if not os.path.exists(keyfile):
                click.echo("Error: Unable to find machine user key file")
                click.echo(f"- fingerprint: {fingerprint}")
                click.echo(f"- keyfile: {keyfile}")

                keyfile = os.path.expanduser("~/.ssh/id_circleci_github")
                if not os.path.exists(keyfile):
                    click.echo("Error: Unable to find circle github key file")
                    click.echo(f"- keyfile: {keyfile}")
                    return

            click.echo(f"Using GITHUB_MACHINE_USER_KEY: {keyfile}")
        else:
            keyfile = None

        args = ["docker", "build", "--rm=false"]
        if self.vars["NPM_TOKEN"]:
            args += ["--build-arg", f"NPM_TOKEN={self.vars['NPM_TOKEN']}"]
        if keyfile:
            args += ["--build-arg", f"GITHUB_MACHINE_USER_KEY={self.vars['NPM_TOKEN']}"]
        args += ["-t", self.vars["DEPLOY_DOCKER_LOCAL_TAG"], "."]
        if not self._exec(args):
            return False

        return True

    def ecs_deploy_image(self):
        if not self._check_environment():
            return

        target_tag = f"{self.vars['DEPLOY_ECR_HOST']}/{self.vars['DEPLOY_APP_NAME']}:{self._get_target_image_tag()}"

        # Login to ECR
        client = self._aws_client("ecr")
        res = client.get_authorization_token(
            registryIds=[self.vars["DEPLOY_ECR_ACCOUNT"]]
        )

        token = base64.b64decode(res["authorizationData"][0]["authorizationToken"])
        username, password = tuple(token.decode().split(":"))

        endpoint = res["authorizationData"][0]["proxyEndpoint"]

        args = [
            "docker",
            "login",
            "--username",
            username,
            "--password",
            password,
            endpoint,
        ]
        if not self._exec(args, redact=True):
            return

        # Tag the image
        args = ["docker", "tag", self.vars["DEPLOY_DOCKER_LOCAL_TAG"], target_tag]
        if not self._exec(args):
            return

        # Push the image
        args = ["docker", "push", target_tag]
        if not self._exec(args):
            return

        return True

    def ecs_deploy(self):
        if not self._check_environment():
            return

        client = self._aws_client("ecs", True)

        # Get family name
        if self.vars["DEPLOY_ECS_SUBFAMILY"]:
            family = (
                f"{self.vars['DEPLOY_APP_NAME']}-{self.vars['DEPLOY_ECS_SUBFAMILY']}"
            )
        else:
            family = self.vars["DEPLOY_APP_NAME"]

        click.echo(f"Family: {family}")

        # Render the template
        if not os.path.exists(self.vars["DEPLOY_TASK_DEF_TEMPLATE"]):
            click.echo(
                f"Error: template '{self.vars['DEPLOY_TASK_DEF_TEMPLATE']}' not found"
            )

        with open(self.vars["DEPLOY_TASK_DEF_TEMPLATE"]) as f:
            template = jinja2.Template(f.read())

        template_vars = self.vars.copy()
        template_vars["DEPLOY_IMAGE_TAG"] = self._get_target_image_tag()
        template_vars[
            "DEPLOY_IMAGE_NAME"
        ] = f"{self.vars['DEPLOY_ECR_HOST']}/{self.vars['DEPLOY_APP_NAME']}:{template_vars['DEPLOY_IMAGE_TAG']}"

        task_def = json.loads(template.render(template_vars))

        # Register the new task def
        if self.vars["DEPLOY_ECS_FARGATE"]:
            res = client.register_task_definition(
                family=family,
                taskRoleArn=f"arn:aws:iam::{self.vars['DEPLOY_AWS_ACCOUNT']}:role/{self.vars['DEPLOY_ECS_FARGATE_TASK_ROLE_NAME']}",
                executionRoleArn=f"arn:aws:iam::{self.vars['DEPLOY_AWS_ACCOUNT']}:role/{self.vars['DEPLOY_ECS_FARGATE_EXECUTION_ROLE_NAME']}",
                networkMode="awsvpc",
                containerDefinitions=task_def,
                requiresCompatibilities=["FARGATE"],
                cpu=self.vars["DEPLOY_ECS_FARGATE_CPU"],
                memory=self.vars["DEPLOY_ECS_FARGATE_MEMORY"],
            )
        else:
            res = client.register_task_definition(
                family=family,
                containerDefinitions=task_def,
            )

        revision_target = res["taskDefinition"]["taskDefinitionArn"]
        click.echo(f"Target revision: {revision_target}")

        # Update the service
        service = family
        click.echo("Updating service:")
        click.echo(f"- cluster: {self.vars['DEPLOY_ECS_CLUSTER_NAME']}")
        click.echo(f"- service: {service}")
        click.echo(f"- taskDefinition: {revision_target}")
        res = client.update_service(
            cluster=self.vars["DEPLOY_ECS_CLUSTER_NAME"],
            service=service,
            taskDefinition=revision_target,
        )

        revision_actual = res["service"]["taskDefinition"]
        if revision_target != revision_actual:
            click.echo("Error updating service: target does not match actual")
            click.echo(f"{revision_target} != {revision_actual}")
            return False

        # Wait for old revision to disappear
        for _ in range(100):
            res = client.describe_services(
                cluster=self.vars["DEPLOY_ECS_CLUSTER_NAME"],
                services=[service],
            )

            finished = False
            for deployment in res["services"][0]["deployments"]:
                if (
                    deployment["taskDefinition"] == revision_target
                    and deployment["rolloutState"] == "COMPLETED"
                ):
                    finished = True
                    break

            if finished:
                click.echo("Success!")
                return True

            click.echo("Waiting for update ...")
            time.sleep(5)

        click.echo("Error: Service update took too long")
        return False

    def _load_vars_from_env(self, vars):
        self.vars = {}
        for var, default in vars:
            self.vars[var] = os.environ.get(var, default)

    def _required_env(self, vars):
        for var in vars:
            if var not in self.vars:
                click.echo(f"Error: {var} is required")
                return False

        return True

    def _check_environment(self):
        return self._required_env(
            [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "DEPLOY_AWS_ACCOUNT",
                "DEPLOY_ECR_ACCOUNT",
                "DEPLOY_ECR_HOST",
            ]
        )

    def _aws_client(self, service, assume_role=False):
        if assume_role:
            boto_sts = boto3.client("sts")
            sts_response = boto_sts.assume_role(
                RoleArn=f"arn:aws:iam::{self.vars['DEPLOY_AWS_ACCOUNT']}:role/{self.vars['DEPLOY_AWS_ROLE']}",
                RoleSessionName="session",
            )
            aws_access_key_id = sts_response["Credentials"]["AccessKeyId"]
            aws_secret_access_key = sts_response["Credentials"]["SecretAccessKey"]
            aws_session_token = sts_response["Credentials"]["SessionToken"]

            client = boto3.client(
                service,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                region_name=self.vars["DEPLOY_AWS_REGION"],
            )

        else:
            client = boto3.client(
                service,
                aws_access_key_id=self.vars["AWS_ACCESS_KEY_ID"],
                aws_secret_access_key=self.vars["AWS_SECRET_ACCESS_KEY"],
                region_name=self.vars["DEPLOY_AWS_REGION"],
            )

        return client

    def _get_target_image_tag(self):
        tag = f"{self.current_date}-{self.vars['DEPLOY_SHA1']}"
        if self.vars["DEPLOY_ENV_TO_TAG"]:
            tag += f"-{self.vars['FLM_ENV']}"

        return tag

    def _display_vars(self, vars):
        for var in vars:
            click.echo(f"- {var} = {self.vars[var]}")

    def _exec(self, args, redact=False):
        if redact:
            click.echo("Executing: [redacted]")
        else:
            click.echo(f"Executing: {args}")
        p = subprocess.run(args)

        if p.returncode != 0:
            click.echo(f"return code: {p.returncode}")
            return False

        return True


@click.group()
def main():
    """Script for deploying stuff to AWS"""


@main.command()
def docker_build():
    """Build a docker image"""
    d = Deployables2()
    if not d.docker_build():
        sys.exit(1)


@main.command()
def ecs_deploy_image():
    """Deploy an ECS image"""
    d = Deployables2()
    if not d.ecs_deploy_image():
        sys.exit(1)


@main.command()
def ecs_deploy():
    """Deploy an ECS service"""
    d = Deployables2()
    if not d.ecs_deploy():
        sys.exit(1)


if __name__ == "__main__":
    main()
