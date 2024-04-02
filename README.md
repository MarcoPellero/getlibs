# Getlibs
This is a simple script to pull the libraries of binaries for pwn challenges in CTFs from docker containers.

It uses the Docker SDK for python, you can install it with `pip install docker`.

Just enter the folder with the challenge files, where the Dockerfile and/or docker-compose.yml are stored, and run this script.

You must tell it the port that the container exposes the challenge at, like this: `getlibs -p=1337`.

It tries to detect whether pwn.red/jail is used from the Dockerfile, and automatically runs the container as privileged if so, and also adjusts the paths it takes the libraries from, but you can also run it with the `--privileged` flag
