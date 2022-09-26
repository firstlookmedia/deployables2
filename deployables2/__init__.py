#!/usr/bin/env python3
import sys
import click

from .deployables2 import Deployables2


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
    """Upload a docker image to ECR"""
    d = Deployables2()
    if not d.ecs_deploy_image():
        sys.exit(1)


@main.command()
def ecs_update_service():
    """Deploy a new task to an ECS service"""
    d = Deployables2()
    if not d.ecs_update_service():
        sys.exit(1)


@main.command()
def lambda_deploy():
    """Deploy a new Lambda function version"""
    d = Deployables2()
    if not d.lambda_deploy():
        sys.exit(1)


@main.command()
def lambda_deploy_event():
    """Deploy a new Lambda event"""
    d = Deployables2()
    if not d.lambda_deploy_event():
        sys.exit(1)


if __name__ == "__main__":
    main()
