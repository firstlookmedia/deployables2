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
            {
                "DEPLOY_AWS_REGION": "us-east-1",
                "DEPLOY_AWS_ROLE": "ops-admin",
                "DEPLOY_DOCKER_LOCAL_TAG": os.environ.get("DEPLOY_APP_NAME", ""),
                "DEPLOY_ECS_FARGATE_CPU": "256",
                "DEPLOY_ECS_FARGATE_MEMORY": "512",
            }
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

        if self.env.get("DEPLOY_GITHUB_MACHINE_USER_KEY_FINGERPRINT"):
            fingerprint = self.env.get(
                "DEPLOY_GITHUB_MACHINE_USER_KEY_FINGERPRINT"
            ).replace(":", "")
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
        if self.env.get("NPM_TOKEN"):
            args += ["--build-arg", "NPM_TOKEN={}".format(self.env.get("NPM_TOKEN"))]
        if keyfile:
            with open(keyfile) as f:
                key_content = f.read()
            args += ["--build-arg", "GITHUB_MACHINE_USER_KEY={}".format(key_content)]
        args += ["-t", self.env.get("DEPLOY_DOCKER_LOCAL_TAG"), "."]
        if not self._exec(args, redact=True):
            return False

        return True

    def ecs_deploy_image(self):
        if not self._check_environment():
            return

        target_tag = "{}/{}:{}".format(
            self.env.get("DEPLOY_ECR_HOST"),
            self.env.get("DEPLOY_ECR_REPO"),
            self._get_target_image_tag(),
        )

        # Login to ECR
        client = self._aws_client("ecr")
        res = client.get_authorization_token(
            registryIds=[self.env.get("DEPLOY_ECR_ACCOUNT")]
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
        args = ["docker", "tag", self.env.get("DEPLOY_DOCKER_LOCAL_TAG"), target_tag]
        if not self._exec(args):
            return

        # Push the image
        args = ["docker", "push", target_tag]
        if not self._exec(args):
            return

        return True

    def ecs_update_service(self):
        if not self._check_environment():
            return

        client = self._aws_client("ecs", True)

        # Get family name
        if self.env.get("DEPLOY_ECS_SUBFAMILY"):
            family = "{}-{}".format(
                self.env.get("DEPLOY_APP_NAME"), self.env.get("DEPLOY_ECS_SUBFAMILY")
            )
        else:
            family = self.env.get("DEPLOY_APP_NAME")

        # Render the template
        if not os.path.exists(self.env.get("DEPLOY_TASK_DEF_TEMPLATE")):
            click.echo(
                "Error: template '{}' not found".format(
                    self.env.get("DEPLOY_TASK_DEF_TEMPLATE")
                )
            )

        with open(self.env.get("DEPLOY_TASK_DEF_TEMPLATE")) as f:
            template = jinja2.Template(f.read())

        template_vars = self.env.copy()
        template_vars["DEPLOY_IMAGE_TAG"] = self._get_target_image_tag()
        template_vars["DEPLOY_IMAGE_NAME"] = "{}/{}:{}".format(
            self.env.get("DEPLOY_ECR_HOST"),
            self.env.get("DEPLOY_ECR_REPO"),
            template_vars["DEPLOY_IMAGE_TAG"],
        )

        task_def = json.loads(template.render(template_vars))

        # Register the new task def
        if self.env.get("DEPLOY_ECS_FARGATE"):
            res = client.register_task_definition(
                family=family,
                taskRoleArn="arn:aws:iam::{}:role/{}".format(
                    self.env.get("DEPLOY_AWS_ACCOUNT"),
                    self.env.get("DEPLOY_ECS_FARGATE_TASK_ROLE_NAME"),
                ),
                executionRoleArn="arn:aws:iam::{}:role/{}".format(
                    self.env.get("DEPLOY_AWS_ACCOUNT"),
                    self.env.get("DEPLOY_ECS_FARGATE_EXECUTION_ROLE_NAME"),
                ),
                networkMode="awsvpc",
                containerDefinitions=task_def,
                requiresCompatibilities=["FARGATE"],
                cpu=self.env.get("DEPLOY_ECS_FARGATE_CPU"),
                memory=self.env.get("DEPLOY_ECS_FARGATE_MEMORY"),
            )
        else:
            res = client.register_task_definition(
                family=family,
                containerDefinitions=task_def,
            )

        revision_target = res["taskDefinition"]["taskDefinitionArn"]

        # Update the service
        service = family
        click.echo("Updating service:")
        click.echo("- cluster: {}".format(self.env.get("DEPLOY_ECS_CLUSTER_NAME")))
        click.echo("- service: {}".format(service))
        click.echo("- taskDefinition: {}".format(revision_target))
        res = client.update_service(
            cluster=self.env.get("DEPLOY_ECS_CLUSTER_NAME"),
            service=service,
            taskDefinition=revision_target,
        )

        revision_actual = res["service"]["taskDefinition"]
        if revision_target != revision_actual:
            click.echo("Error updating service: target does not match actual")
            click.echo("{} != {}".format(revision_target, revision_actual))
            return False

        # Wait for old revision to disappear
        for count in range(1000):
            res = client.describe_services(
                cluster=self.env.get("DEPLOY_ECS_CLUSTER_NAME"),
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

            click.echo("{}s Waiting for update ...".format(count * 5))
            time.sleep(5)

        click.echo("Error: Service update took too long")
        return False

    def _load_vars_from_env(self, defaults):
        self.env = defaults.copy()
        for var in os.environ:
            self.env[var] = os.environ.get(var, "")

    def _required_env(self, vars):
        for var in vars:
            if (
                var not in self.env
                or self.env.get(var) is None
                or self.env.get(var) == ""
            ):
                click.echo("Error: {} is required".format(var))
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
                RoleArn="arn:aws:iam::{}:role/{}".format(
                    self.env.get("DEPLOY_AWS_ACCOUNT"), self.env.get("DEPLOY_AWS_ROLE")
                ),
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
                region_name=self.env.get("DEPLOY_AWS_REGION"),
            )

        else:
            client = boto3.client(
                service,
                aws_access_key_id=self.env.get("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=self.env.get("AWS_SECRET_ACCESS_KEY"),
                region_name=self.env.get("DEPLOY_AWS_REGION"),
            )

        return client

    def _get_target_image_tag(self):
        tag = "{}-{}".format(self.current_date, self.env.get("DEPLOY_SHA1"))
        if self.env.get("DEPLOY_ENV_TO_TAG"):
            tag += "-{}".format(self.env.get("FLM_ENV"))

        return tag

    def _display_vars(self, vars):
        for var in vars:
            click.echo("- {} = {}".format(var, self.env.get(var)))

    def _exec(self, args, redact=False):
        if redact:
            click.echo("Executing: [redacted]")
        else:
            click.echo("Executing: {}".format(args))
        p = subprocess.run(args)

        if p.returncode != 0:
            click.echo("return code: {}".format(p.returncode))
            return False

        return True
