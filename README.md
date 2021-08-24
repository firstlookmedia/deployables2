# Deployables 2

A basket of deploy scripts, ported [from bash](https://github.com/firstlookmedia/deployables) to python 3 and hopefully simplified.

These are the arguments that are implemented:

```
$ poetry run deployables
Usage: deployables2 [OPTIONS] COMMAND [ARGS]...

  Script for deploying stuff to AWS

Options:
  --help  Show this message and exit.

Commands:
  docker-build      Build a docker image
  ecs-deploy        Deploy an ECS service
  ecs-deploy-image  Deploy an ECS image
```

Most of the input happens through environment variables.
