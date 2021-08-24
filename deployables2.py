#!/usr/bin/env python3
import os
import subprocess
import datetime
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
                ("DEPLOY_DOCKERFILE", "./Dockerfile"),
                ("DEPLOY_DOCKER_LOCAL_TAG", os.environ.get("DEPLOY_APP_NAME")),
                ("DEPLOY_ECR_ACCOUNT", None),
                ("DEPLOY_ECR_HOST", None),
                ("DEPLOY_ECS_CLUSTER_NAME", "stargate"),
                ("DEPLOY_GITHUB_MACHINE_USER_KEY_FINGERPRINT", None),
                ("DEPLOY_SHA1", None),
                ("FLM_ENV", None),
                ("NPM_TOKEN", None),
            ]
        )

        self.current_date = datetime.datetime.now().strftime("%Y%m%d")

    def docker_build(self):
        click.echo("Building docker image")
        if not self._required_env(["deploy_dockerfile", "deploy_docker_local_tag"]):
            return

        click.echo("- DEPLOY_DOCKERFILE: {}".format(self.deploy_dockerfile))
        click.echo("- DEPLOY_DOCKER_LOCAL_TAG: {}".format(self.deploy_docker_local_tag))

        if self.deploy_github_machine_user_key_fingerprint:
            fingerprint = self.deploy_github_machine_user_key_fingerprint.replace(
                ":", ""
            )
            keyfile = os.path.expanduser("~/.ssh/id_{}".format(fingerprint))

            if not os.path.exists(keyfile):
                click.echo("Error: Unable to find machine user key file")
                click.echo("- fingerprint: {}".format(fingerprint))
                click.echo("- keyfile: {}".format(keyfile))

                keyfile = os.path.expanduser("~/.ssh/id_circleci_github")
                if not os.path.exists(keyfile):
                    click.echo("Error: Unable to find circle github key file")
                    click.echo("- keyfile: {}".format(keyfile))
                    return

            click.echo("Using GITHUB_MACHINE_USER_KEY: {}".format(keyfile))
        else:
            keyfile = None

        args = ["docker", "build", "--rm=false"]
        if self.npm_token:
            args += ["--build-arg", "NPM_TOKEN={}".format(self.npm_token)]
        if keyfile:
            args += ["--build-arg", "GITHUB_MACHINE_USER_KEY={}".format(self.npm_token)]
        args += ["-t", self.deploy_docker_local_tag, "-f", self.deploy_dockerfile]
        self._exec(args)

    def ecs_deploy_image(self):
        if not self._check_environment():
            return

        target_tag = "{}/{}:{}".format(
            self.deploy_ecr_host, self.deploy_app_name, self._get_target_image_tag()
        )

        # Login to ECR
        client = self._aws_client("ecr")
        res = client.get_authorization_token(registryIds=[self.deploy_ecr_account])
        token = res["authorizationData"][0]["authorizationToken"]
        args = [
            "docker",
            "login",
            "-u",
            "AWS",
            "-p",
            token,
            "-e",
            "none",
            "https://{}.dkr.ecr.us-east-1.amazonaws.com".format(
                self.deploy_ecr_account
            ),
        ]
        if not self._exec(args):
            return

        # Tag the image
        args = ["docker", "tag", self.deploy_docker_local_tag, target_tag]
        if not self._exec(args):
            return

        # Push the image
        args = ["docker", "push", target_tag]
        if not self._exec(args):
            return

    def _set_attributes_from_env(self, vars):
        for var, default in vars:
            self.__setattr__(var.lower(), os.environ.get(var, default))

    def _required_env(self, vars):
        for var in vars:
            if self.__getattribute__(var) is None:
                click.echo("Error: {} is required".format(var))
                return False

        return True

    def _check_environment(self):
        return self._required_env(
            "aws_access_key_id",
            "aws_secret_access_key",
            "deploy_app_name",
            "deploy_aws_account",
            "deploy_ecr_account",
            "deploy_ecr_host",
        )

    def _aws_client(self, service):
        client = boto3.client(
            service,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
        )
        return client

    def _get_target_image_tag(self):
        tag = "{}-{}".format(self.current_date, self.deploy_sha1)
        if self.deploy_env_to_tag:
            tag += "-{}".format(self.flm_env)

        return tag

    def _exec(self, args):
        click.echo("Executing: {}".format(args))
        p = subprocess.run(args)

        if p.returncode != 0:
            click.echo("return code: {}".format(p.returncode))
            return False

        return True


@click.group()
def main():
    """Script for deploying stuff to AWS"""


@main.command()
def docker_build():
    """Build a docker image"""
    d = Deployables2()
    d.docker_build()


@main.command()
def ecs_deploy_image():
    """Deploy an ECS image"""
    d = Deployables2()
    d.ecs_deploy_image()


@main.command()
def ecs_deploy():
    """Deploy an ECS service"""
    click.echo("Not implemented")


if __name__ == "__main__":
    main()
