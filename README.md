# Deployables 2

A basket of deploy scripts, ported [from bash](https://github.com/firstlookmedia/deployables) to python 3 and hopefully simplified.

These are the arguments that are implemented:

```
$ deployables2
Usage: deployables2 [OPTIONS] COMMAND [ARGS]...

  Script for deploying stuff to AWS

Options:
  --help  Show this message and exit.

Commands:
  docker-build        Build a docker image
  ecs-deploy-image    Upload a docker image to ECR
  ecs-update-service  Deploy a new task to an ECS service
```

Most of the input happens through environment variables.

## Technology

In order to make this run on a variety of older platforms, dependencies are defined in `requirements.txt` and the module is installed via `setup.py`.

Only use features available in python 3.7.3, which is the latest available in `buster`.

The simplest way to install deployables2 in debian-based containers for CI:

```sh
sudo apt-get update --allow-releaseinfo-change
sudo apt-get install -y python3 python3-pip
git clone https://github.com/firstlookmedia/deployables2.git /tmp/deployables2
cd /tmp/deployables2
git checkout v0.1.7
pip3 install -r requirements.txt
python3 setup.py install --user
```