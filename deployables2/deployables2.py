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
        print("Task definition:\n{}\n".format(rendered_template))
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
            "DEPLOY_LAMBDA_SOURCE_DIR",
            "DEPLOY_LAMBDA_ZIP_FULLPATH",
            "DEPLOY_LAMBDA_ZIP_VERSION",
        ]):
            return False

        function_name = self.env.get("DEPLOY_LAMBDA_FUNCTION_NAME")
        tag = self.env.get("DEPLOY_LAMBDA_ZIP_VERSION")

        # render the environment template with the current env variables
        with open(self.env.get("DEPLOY_LAMBDA_FUNCTION_ENV_TEMPLATE"), "r") as f:
            function_environment_template = jinja2.Template(f.read())
        function_environment_variables = self.env.copy()
        function_environment = json.loads(
            function_environment_template.render(function_environment_variables)
        )

        lambda_client = self._aws_client("lambda", True)

        code = self._lambda_create_archive(
            lambda_client = lambda_client,
            output_path = self.env.get("DEPLOY_LAMBDA_ZIP_FULLPATH"),
            source_directory = self.env.get("DEPLOY_LAMBDA_SOURCE_DIR"),
        )
        if code is None:
            click.echo("Could not create the archive")
            return False

        click.echo("Checking for existing {} function...".format(function_name))
        try:
            existing_function = lambda_client.get_function_configuration(
                FunctionName = function_name,
            )
            click.echo("Found {}".format(existing_function["FunctionArn"]))
        except lambda_client.exceptions.ResourceNotFoundException:
            existing_function = None
            click.echo("No function found")
        click.echo("")

        config = {
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

        for key, value in dict(config).items():
            if value is None:
                del config[key]

        if existing_function is None:
            new_function = self._lambda_create_function(
                code = code,
                config = config,
                lambda_client = lambda_client,
            )

            publish_config = {
                "CodeSha256": new_function["CodeSha256"],
                "Description": tag,
                "FunctionName": function_name,
                "RevisionId": new_function["RevisionId"],
            }

            click.echo("Created {} (revision: {})".format(new_function["FunctionArn"], new_function["RevisionId"]))
            click.echo("")
        else:
            updated_function = self._lambda_update_function(
                code = code,
                config = config | {
                    "RevisionId": existing_function["RevisionId"]
                },
                lambda_client = lambda_client,
            )

            publish_config = {
                "CodeSha256": updated_function["CodeSha256"],
                "Description": tag,
                "FunctionName": function_name,
                "RevisionId": updated_function["RevisionId"],
            }

            click.echo("Updated {} (revision: {})".format(updated_function["FunctionArn"], updated_function["RevisionId"]))
            click.echo("")

        published_function = self._lambda_publish_version(
            config = publish_config,
            lambda_client = lambda_client,
        )

        click.echo("Published new version of {}:".format(function_name))
        click.echo("- arn: {}".format(published_function["FunctionArn"]))
        click.echo("- hash: {}".format(published_function["CodeSha256"]))
        click.echo("- revision: {}".format(published_function["RevisionId"]))
        click.echo("- version: {}".format(published_function["Version"]))
        click.echo("")

        click.echo("DONE")

        return True

    def _lambda_create_archive(self, lambda_client, output_path, source_directory):
        # TODO check if output_path refers to a pre-built .zip and use it as is, if so

        archive_format = "zip"
        archive_name = pathlib.Path(output_path).with_suffix('')

        click.echo("Creating {} archive of {}...".format(archive_format, source_directory))

        ignore_patterns = [".git"]

        with tempfile.TemporaryDirectory() as temp_directory:
            # create a temporary copy of the project source, ignoring unnecessary files/directories
            shutil.copytree(
                source_directory,
                temp_directory,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(*ignore_patterns),
            )

            # create a .zip of the project source
            shutil.make_archive(
                archive_name,
                archive_format,
                temp_directory,
            )

        click.echo("Created {}".format(output_path))
        click.echo("")

        account_settings = lambda_client.get_account_settings()
        max_archive_bytes = account_settings["AccountLimit"]["CodeSizeZipped"]

        archive_size = os.path.getsize(output_path)
        if archive_size >= max_archive_bytes:
            click.echo("Archive is too large to upload directly (limit: {}B)".format(max_archive_bytes))

            # TODO upload large archives to S3 and then return {"S3Bucket": ..., "S3Key": ..., "S3ObjectVersion: ..."}

            return None

        with open(output_path, "rb") as f:
            function_code = { "ZipFile": f.read() }

        return function_code

    def _lambda_create_function(self, code, config, lambda_client):
        new_function = lambda_client.create_function(**(config | { "Code": code, "PackageType": "Zip" }))

        function_arn = new_function['FunctionArn']

        [new_function, error] = self._poll_for_update(
            is_finished = lambda response: response["State"] != "Pending" and response["LastUpdateStatus"] != "InProgress",
            perform_request = lambda: lambda_client.get_function_configuration(FunctionName = function_arn),
            start_message = "Creating function...".format(function_arn),
        )

        if error:
            click.echo("Lambda took too long to create the function")
            return False

        if new_function["LastUpdateStatus"] == "Failed" or new_function["State"] == "Failed":
            click.echo("Failed to create the function: {}".format(new_function["LastUpdateStatusReason"] or new_function["StateReason"]))
            return False

        return new_function

    def _lambda_publish_version(self, config, lambda_client):
        published_function = lambda_client.publish_version(**config)
        function_arn_with_version = published_function["FunctionArn"]

        [published_function, error] = self._poll_for_update(
            is_finished = lambda response: response["State"] != "Pending" and response["LastUpdateStatus"] != "InProgress",
            perform_request = lambda: lambda_client.get_function_configuration(FunctionName = function_arn_with_version),
            start_message = "Publishing version...",
        )

        if error:
            click.echo("Lambda took too long to publish the new version")
            return False

        if published_function["LastUpdateStatus"] == "Failed" or published_function["State"] == "Failed":
            click.echo("Failed to publish the version: {}".format(published_function["LastUpdateStatusReason"] or published_function["StateReason"]))
            return False

        return published_function

    def _lambda_update_function(self, code, config, lambda_client):
        updated_function = lambda_client.update_function_configuration(**config)
        [updated_function, error] = self._poll_for_update(
            is_finished = lambda response: response["State"] != "Pending" and response["LastUpdateStatus"] != "InProgress",
            perform_request = lambda: lambda_client.get_function_configuration(FunctionName = config["FunctionName"]),
            start_message = "Updating function configuration...",
        )

        if error:
            click.echo("Lambda took too long to update the function's configuration")
            return False

        if updated_function["LastUpdateStatus"] == "Failed" or updated_function["State"] == "Failed":
            click.echo("Failed to update the function: {}".format(updated_function["LastUpdateStatusReason"] or updated_function["StateReason"]))
            return False

        click.echo("Updated function configuration (revision: {})".format(updated_function["RevisionId"]))
        click.echo("")

        updated_function_code = code | {
            "FunctionName": config["FunctionName"],
            "Publish": False,
            "RevisionId": updated_function["RevisionId"],
        }

        updated_function = lambda_client.update_function_code(**updated_function_code)

        [updated_function, error] = self._poll_for_update(
            is_finished = lambda response: response["State"] != "Pending" and response["LastUpdateStatus"] != "InProgress",
            perform_request = lambda: lambda_client.get_function_configuration(FunctionName = config["FunctionName"]),
            start_message = "Updating function code...",
        )

        if error:
            click.echo("Lambda took too long to update the function's code")
            return False

        if updated_function["LastUpdateStatus"] == "Failed" or updated_function["State"] == "Failed":
            click.echo("Failed to create the function: {}".format(updated_function["LastUpdateStatusReason"] or updated_function["StateReason"]))
            return False

        click.echo("Updated function code (revision: {})".format(updated_function["RevisionId"]))
        click.echo("")

        return updated_function


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

    def _poll_for_update(self, is_finished, perform_request, start_message, delay_between_requests=5, max_attempts=1000):
        click.echo(start_message, nl=False)

        attempt = 1
        while attempt < max_attempts:
            response = perform_request()

            if is_finished(response):
                click.echo("")
                return [response, None]

            attempt += 1
            click.echo(".", nl=False)
            time.sleep(delay_between_requests)

        click.echo("")
        [None, "too many attempts"]
