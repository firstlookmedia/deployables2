import base64
import boto3
import click
import datetime
import jinja2
import json
import os
import shutil
import subprocess
import tempfile
import time


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
        if not self._required_env([
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "DEPLOY_AWS_ACCOUNT",
            "DEPLOY_ECR_ACCOUNT",
            "DEPLOY_ECR_HOST",
        ]):
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
        if not self._required_env([
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "DEPLOY_AWS_ACCOUNT",
            "DEPLOY_ECR_ACCOUNT",
            "DEPLOY_ECR_HOST",
        ]):
            return

        client = self._aws_client("ecs", True)

        # Get family names
        # Where:
        #   DEPLOY_APP_NAME is 'topic'
        #   DEPLOY_ECS_SUBFAMILY is 'stargate'
        #   DEPLOY_ECS_FAMILIES is '2'
        # The family name would be 'topic-2-stargate',
        if self.env.get("DEPLOY_ECS_SUBFAMILY"):
            if self.env.get("DEPLOY_ECS_FAMILIES"):
                family = "{}-{}-{}".format(
                    self.env.get("DEPLOY_APP_NAME"),
                    self.env.get("DEPLOY_ECS_FAMILIES"),
                    self.env.get("DEPLOY_ECS_SUBFAMILY"),
                )
            else:
                family = "{}-{}".format(
                    self.env.get("DEPLOY_APP_NAME"), self.env.get("DEPLOY_ECS_SUBFAMILY")
                )
        else:
            if self.env.get("DEPLOY_ECS_FAMILIES"):
                family = "{}-{}".format(
                    self.env.get("DEPLOY_APP_NAME"),
                    self.env.get("DEPLOY_ECS_FAMILIES"),
                )
            else:
                family = self.env.get("DEPLOY_APP_NAME")

        service = family

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

        rendered_template = template.render(template_vars)
        print(f"Task definition:\n{rendered_template}\n")
        task_def = json.loads(rendered_template)

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
        click.echo("Updating service:")
        click.echo("- cluster: {}".format(self.env.get("DEPLOY_ECS_CLUSTER_NAME")))
        click.echo("- family: {}".format(family))
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

    def lambda_deploy(self):
        if not self._required_env([
            "AWS_ACCESS_KEY_ID",
            "AWS_SECRET_ACCESS_KEY",
            "DEPLOY_AWS_ACCOUNT",
            "DEPLOY_LAMBDA_FUNCTION_ENV_TEMPLATE",
            "DEPLOY_LAMBDA_FUNCTION_MEMORY_SIZE",
            "DEPLOY_LAMBDA_FUNCTION_NAME",
            "DEPLOY_LAMBDA_FUNCTION_ROLE",
            "DEPLOY_LAMBDA_FUNCTION_RUNTIME",
            "DEPLOY_LAMBDA_FUNCTION_TIMEOUT",
            "DEPLOY_LAMBDA_ZIP_VERSION",
        ]):
            return False

        function_name = self.env.get("DEPLOY_LAMBDA_FUNCTION_NAME")

        # TODO check if DEPLOY_LAMBDA_ZIP_FULLPATH refers to a pre-built .zip and use it as is, if so
        archive_path = self._create_lambda_archive()
        if not archive_path:
            return False

        archive_size = os.path.getsize(archive_path)
        if archive_size >= 50_000_000:
            # TODO upload the archive to S3 and use that instead of erroring out
            click.echo("Error: archive is {} bytes, which is too large to upload directly (max: 50MB)".format(archive_size))
            return False

        lambda_client = self._aws_client("lambda", True)

        existing_function = lambda_client.get_function(
            FunctionName = function_name,
        )

        if existing_function:
            function_arn = existing_function['Configuration']['FunctionArn']
            existing_revision = existing_function['Configuration']['RevisionId']

            click.echo("Updating function:")
            click.echo("- arn: {}".format(function_arn))
            click.echo("- existingRevision: {}".format(existing_revision))

            # TODO update the existing function's configuration
            # TODO update the existing function's code
            # TODO publish the new version

            return False
        else:
            click.echo("Creating function")
            click.echo("- name: {}".format(function_name))

            return False

    def _create_lambda_archive(self):
        if not self._required_env([
            "DEPLOY_LAMBDA_SOURCE_DIR",
            "DEPLOY_LAMBDA_ZIP_FULLPATH",
        ]):
            return None

        source_directory = self.env.get("DEPLOY_LAMBDA_SOURCE_DIR")
        full_archive_path = self.env.get("DEPLOY_LAMBDA_ZIP_FULLPATH")

        ignore_patterns = [".git"]

        with tempfile.TemporaryDirectory() as archivable_directory:
            click.echo("Copying source (minus any unnecessary assets) to a temporary directory:")
            click.echo("- source: {}".format(source_directory))
            click.echo("- temporary directory: {}".format(archivable_directory))
            click.echo("- ignore patterns: {}".format(ignore_patterns))

            # create a temporary copy of the project source, ignoring unnecessary files/directories
            shutil.copytree(
                source_directory,
                archivable_directory,
                ignore=shutil.ignore_patterns(*ignore_patterns),
            )

            archive_name = os.path.join(
                os.path.dirname(full_archive_path),
                os.path.basename(full_archive_path),    # note: no extension
            )
            archive_format = "zip"
            click.echo("Building an archive of the source:")
            click.echo("- directory: {}".format(archivable_directory))
            click.echo("- output: {}.{}".format(archive_name, archive_format))

            # create a .zip of the project source
            archive = shutil.make_archive(
                archive_name,
                archive_format,
                archivable_directory,
            )

        return archive

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
