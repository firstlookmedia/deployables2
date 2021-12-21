import base64
import boto3
import click
import datetime
import jinja2
import json
import os
import pathlib
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

        # render the environment template with the current env variables
        with open(self.env.get("DEPLOY_LAMBDA_FUNCTION_ENV_TEMPLATE"), "r") as f:
            function_environment_template = jinja2.Template(f.read())
        function_environment_variables = self.env.copy()
        function_environment = json.loads(
            function_environment_template.render(function_environment_variables)
        )

        # TODO check if DEPLOY_LAMBDA_ZIP_FULLPATH refers to a pre-built .zip and use it as is, if so
        archive_path = self._create_lambda_archive()
        if not archive_path:
            return False

        archive_size = os.path.getsize(archive_path)
        if archive_size >= 50_000_000:
            # TODO upload the archive to S3
            # TODO function_code = dict(S3Bucket="...", S3Key="...", S3ObjectVersion="...")
            click.echo("Error: archive is {} bytes, which is too large to upload directly (max: 50MB)".format(archive_size))
            return False
        else:
            with open(archive_path, "rb") as f:
                function_code = { "ZipFile": f.read() }

        lambda_client = self._aws_client("lambda", True)
        function_name = self.env.get("DEPLOY_LAMBDA_FUNCTION_NAME")

        try:
            existing_function = lambda_client.get_function_configuration(
                FunctionName = function_name,
            )
        except lambda_client.exceptions.ResourceNotFoundException:
            existing_function = None

        function_config = {
            "Description": self.env.get("DEPLOY_LAMBDA_FUNCTION_DESCRIPTION"),
            "Environment": function_environment,
            "FunctionName": function_name,
            "Handler": self.env.get("DEPLOY_LAMBDA_FUNCTION_HANDLER") or "index.handler",
            "MemorySize": int(self.env.get("DEPLOY_LAMBDA_FUNCTION_MEMORY_SIZE")),
            "Role": "arn:aws:iam::{}:role/{}".format(
                self.env.get("DEPLOY_AWS_ACCOUNT"),
                self.env.get("DEPLOY_LAMBDA_FUNCTION_ROLE"),
            ),
            "Runtime": self.env.get("DEPLOY_LAMBDA_FUNCTION_RUNTIME"),
            "Timeout": int(self.env.get("DEPLOY_LAMBDA_FUNCTION_TIMEOUT")),
        }

        for key, value in dict(function_config).items():
            if value is None:
                del function_config[key]

        if existing_function is None:
            new_function_config = function_config | {
                "Code": function_code,
                "PackageType": "Zip",
                "Publish": False,
            }

            click.echo("Creating new {} function...".format(function_name))
            new_function = lambda_client.create_function(**new_function_config)
            function_arn = new_function['FunctionArn']

            [new_function, error] = self._poll_for_update(
                "Waiting for {} to be fully created...".format(function_arn),
                lambda: lambda_client.get_function_configuration(FunctionName = function_arn),
                lambda response: response["State"] != "Pending",
            )

            if error:
                click.echo("Lambda took too long to create the function")
                return False

            if new_function["State"] == "Failed":
                click.echo("Failed to create the function: {}".format(new_function["StateReason"]))
                return False

            code_sha256_to_publish = new_function["CodeSha256"]
            revision_to_publish = new_function["RevisionId"]

            click.echo("Created {} function (state: {}, revision: {})".format(function_arn, new_function["State"], revision_to_publish))
            click.echo("")
        else:
            updated_function_config = function_config | {
                "RevisionId": existing_function["RevisionId"]
            }

            click.echo("Updating configuration for {}...".format(function_name))
            updated_function = lambda_client.update_function_configuration(**updated_function_config)

            # TODO remove
            click.echo(json.dumps(updated_function, indent = 2))

            [updated_function, error] = self._poll_for_update(
                "Checking for updated configuration for {}...".format(function_name),
                lambda: lambda_client.get_function_configuration(FunctionName = function_name),
                lambda response: response["State"] != "Pending",
            )

            if error:
                click.echo("Lambda took too long to update the function's configuration")
                return False

            if updated_function["State"] == "Failed":
                click.echo("Failed to update the function's configuration: {}".format(updated_function["StateReason"]))
                return False

            click.echo("Updated configuration for {} (state: {}, revision: {})".format(function_name, updated_function["State"], updated_function["RevisionId"]))
            click.echo("")

            # TODO remove
            click.echo(json.dumps(updated_function, indent = 2))

            click.echo("Updating code for {}...".format(function_name))

            updated_function_code = function_code | {
                "FunctionName": function_name,
                "Publish": False,
                "RevisionId": updated_function["RevisionId"],
            }
            updated_function = lambda_client.update_function_code(**updated_function_code)

            # TODO remove
            click.echo(json.dumps(updated_function, indent = 2))

            [updated_function, error] = self._poll_for_update(
                "Checking for updated configuration for {}...".format(function_name),
                lambda: lambda_client.get_function_configuration(FunctionName = function_name),
                lambda response: response["State"] != "Pending",
            )

            if error:
                click.echo("Lambda took too long to update the function's code")
                return False

            if updated_function["State"] == "Failed":
                click.echo("Failed to update the function's code: {}".format(updated_function["StateReason"]))
                return False

            click.echo("Updated code for {} (state: {}, revision: {})".format(function_name, updated_function["State"], updated_function["RevisionId"]))
            click.echo("")

            # TODO remove
            click.echo(json.dumps(updated_function, indent = 2))

            code_sha256_to_publish = updated_function["CodeSha256"]
            revision_to_publish = updated_function["RevisionId"]

        click.echo("Publishing new version of {} (revision: {})...".format(function_name, revision_to_publish))
        published_function = lambda_client.publish_version(
            CodeSha256 = code_sha256_to_publish,
            FunctionName = function_name,
            RevisionId = revision_to_publish
        )
        versioned_function_arn = published_function['FunctionArn']

        [published_function, error] = self._poll_for_update(
            "Waiting for the new version of {} to publish...".format(function_name),
            lambda: lambda_client.get_function_configuration(FunctionName = versioned_function_arn),
            lambda response: response["State"] != "Pending",
        )

        if error:
            click.echo("Lambda took too long to publish the new version")
            return False

        if published_function["State"] == "Failed":
            click.echo("The new version failed to publish: {}".format(published_function["StateReason"]))
            return False

        click.echo("Published {} (state: {}, revision: {})".format(versioned_function_arn, published_function["State"], published_function["RevisionId"]))
        return True

    def _create_lambda_archive(self):
        if not self._required_env([
            "DEPLOY_LAMBDA_SOURCE_DIR",
            "DEPLOY_LAMBDA_ZIP_FULLPATH",
        ]):
            return None

        full_source_directory = self.env.get("DEPLOY_LAMBDA_SOURCE_DIR")
        full_archive_path = self.env.get("DEPLOY_LAMBDA_ZIP_FULLPATH")

        archive_format = "zip"
        archive_name = pathlib.Path(full_archive_path).with_suffix('')

        click.echo("Creating {} archive of {}...".format(archive_format, full_source_directory))

        ignore_patterns = [".git"]

        with tempfile.TemporaryDirectory() as temp_directory:
            # create a temporary copy of the project source, ignoring unnecessary files/directories
            shutil.copytree(
                full_source_directory,
                temp_directory,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(*ignore_patterns),
            )

            # create a .zip of the project source
            archive = shutil.make_archive(
                archive_name,
                archive_format,
                temp_directory,
            )

        click.echo("Created {}".format(full_archive_path))
        click.echo("")

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

    def _poll_for_update(self, start_message, request, is_finished, max_attempts=1000, delay_between_requests=5):
        click.echo(start_message, nl=False)

        attempt = 1
        while attempt < max_attempts:
            response = request()

            if is_finished(response):
                click.echo("")
                return [response, None]

            attempt += 1
            click.echo(".", nl=False)
            time.sleep(delay_between_requests)

        click.echo("")
        [None, "too many attempts"]
