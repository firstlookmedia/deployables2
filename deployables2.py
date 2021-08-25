#!/usr/bin/env python3
import sys
import os
import subprocess
import datetime
import base64
import click
import boto3


class Deployables2:
    def __init__(self):
        # Set class attributes from environment variables, like self.aws_access_key_id, etc.
        self._set_attributes_from_env(
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
                ("DEPLOY_ECR_HOST", None),
                ("DEPLOY_ECS_CLUSTER_NAME", "stargate"),
                ("DEPLOY_ECS_SUBFAMILY", None),
                ("DEPLOY_ENV_TO_TAG", None),
                ("DEPLOY_GITHUB_MACHINE_USER_KEY_FINGERPRINT", None),
                ("DEPLOY_SHA1", None),
                ("FLM_ENV", None),
                ("NPM_TOKEN", None),
            ]
        )

        self.current_date = datetime.datetime.now().strftime("%Y%m%d")

    def docker_build(self):
        click.echo("Building docker image")
        if not self._required_env(["deploy_docker_local_tag"]):
            return

        self._display_vars(
            [
                "deploy_docker_local_tag",
                "deploy_github_machine_user_key_fingerprint",
            ]
        )

        if self.deploy_github_machine_user_key_fingerprint:
            fingerprint = self.deploy_github_machine_user_key_fingerprint.replace(
                ":", ""
            )
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
        if self.npm_token:
            args += ["--build-arg", f"NPM_TOKEN={self.npm_token}"]
        if keyfile:
            args += ["--build-arg", f"GITHUB_MACHINE_USER_KEY={self.npm_token}"]
        args += ["-t", self.deploy_docker_local_tag, "."]
        if not self._exec(args):
            return False

        return True

    def ecs_deploy_image(self):
        if not self._check_environment():
            return

        target_tag = f"{self.deploy_ecr_host}/{self.deploy_app_name}:{self._get_target_image_tag()}"

        # Login to ECR
        client = self._aws_client("ecr")
        res = client.get_authorization_token(registryIds=[self.deploy_ecr_account])

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
        args = ["docker", "tag", self.deploy_docker_local_tag, target_tag]
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

        tag = self._get_target_image_tag()

        # Deploy the image
        if not self.ecs_deploy_image():
            return False

        # Update the service
        if not self._ecs_deploy_task(tag, self.deploy_ecs_subfamily):
            return False

    def _ecs_deploy_task(self, tag, subfamily):
        image = f"{self.deploy_ecr_host}/{self.deploy_app_name}:{tag}"

        if subfamily:
            family = f"{self.deploy_app_name}-{subfamily}"
        else:
            family = self.deploy_app_name

        click.echo(f"Current task definition: {family}")

        client = self._aws_client("ecs")
        ret = client.describe_services(
            cluster=self.deploy_ecs_cluster_name, services=[family]
        )
        if len(ret["services"]) == 0:
            return False

        previous_task_def = ret["services"][0]["taskDefinition"]
        click.echo(f"Previous task definition: {previous_task_def}")

        if not os.path.exists():
            click.echo(f"Error: template '{self.deploy_task_def_template}' not found")

        # TODO: finish implementing

    def _set_attributes_from_env(self, vars):
        for var, default in vars:
            self.__setattr__(var.lower(), os.environ.get(var, default))

    def _required_env(self, vars):
        for var in vars:
            if self.__getattribute__(var) is None:
                click.echo(f"Error: {var} is required")
                return False

        return True

    def _check_environment(self):
        return self._required_env(
            [
                "aws_access_key_id",
                "aws_secret_access_key",
                "deploy_aws_account",
                "deploy_ecr_account",
                "deploy_ecr_host",
            ]
        )

    def _aws_client(self, service):
        client = boto3.client(
            service,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            region_name=self.deploy_aws_region,
        )
        return client

    def _get_target_image_tag(self):
        tag = f"{self.current_date}-{self.deploy_sha1}"
        if self.deploy_env_to_tag:
            tag += f"-{self.flm_env}"

        return tag

    def _display_vars(self, vars):
        for var in vars:
            click.echo(f"- {var} = {self.__getattribute__(var)}")

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
