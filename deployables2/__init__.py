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
