#!/usr/bin/env python3

import docker
import argparse
import socket
import time
import os
import subprocess
import docker.errors
import docker.models.containers
import psutil
import atexit

def get_procs(container: docker.models.containers.Container) -> list[psutil.Process]:
	top = container.top()
	procs = top["Processes"]
	pids = [int(proc[1]) for proc in procs]
	return [psutil.Process(pid) for pid in pids]

def choose_proc(before: list[psutil.Process], after: list[psutil.Process], args: argparse.Namespace) -> psutil.Process:
	new = list(set(after) - set(before))
	print(f"New PIDs: {[proc.pid for proc in new]}")
	if len(new) == 1:
		return new[0]

	if not args.no_proc_heuristics:
		"""
		could use a command blacklist for socat, socaz, nsjail, xinetd, ecc...
		but we can also bypass these using a more general solution of looking at parents and children
		neither of these work too well for a binary that spawns a child with different libs, and you might want to
		get both of their libs, but that's what this option is for: you can disable it and explicit the target process

		just getting the highest pid doesn't work because they wrap around after reaching a pid_max value (/proc/sys/kernel/pid_max)
		pid_max isn't necessarily that high; it's 4M~ on my pc, 32k~ & 64k~ for many other people
		i get 600k as pids right now and i've started my computer just a few hours ago :P
		it would be very rare for pids to wrap around HERE, but if it didn't happen and it wasn't handled, someone would have a very bad day if they didn't notice :/
		"""

		print("Warning: the proc-heuristics option is set to TRUE (default); using heuristics to determine the target process. Disable with --no-proc-heuristics")
		leaves = [proc for proc in new if not proc.children()]
		if len(leaves) == 1:
			return leaves[0]
		
		print(f"Couldn't determine target process; multiple 'leaf' (childless) processes found: {leaves}")
		print("Reverting to manual selection")

	print("Multiple new processes detected, please choose the target PID:")
	print("\t-1: Stop the container")
	for proc in new:
		print(f"\t{proc.pid}: {' '.join(proc.cmdline())}")

	pid = int(input("PID: "))
	if pid == -1:
		return None

	proc = next((proc for proc in new if proc.pid == pid), None)
	if proc is None:
		print("Invalid PID; stopping the container")
	
	return proc

def is_pwnred() -> bool:
	if os.path.exists("./Dockerfile"):
		with open("./Dockerfile") as f:
			return "FROM pwn.red/jail" in f.read()
	
	return False

def build_from_dockerfile(client: docker.DockerClient, args: argparse.Namespace) -> str:
	if is_pwnred():
		args.privileged = True
		print("Detected pwn.red/jail Dockerfile, running as privileged")
	
	# run as subprocess so that the user can see the container buile
	subprocess.run(["docker", "build", "."])
	# and then re run to get the image id
	img, _ = client.images.build(path=".")
	print(f"Image: {img.id}")

	container = client.containers.run(img, detach=True, ports={args.port: args.port}, privileged=args.privileged)
	return container.id

def build_from_compose() -> str:
	subprocess.run(["docker", "compose", "up", "--build", "-d"])
	# actually could get the container name from the docker compose subprocess stderr
	# i won't now cause this works and i think that might be 'unstable',
	# especially if the container immediately starts printing stuff
	result = subprocess.run(["docker", "compose", "ps", "-q"], capture_output=True)
	return result.stdout.decode().strip()

def read_super(path: str) -> str:
	try:
		with open(path) as f:
			return f.read()
	except PermissionError:
		print("Error: Permission denied; trying again with sudo")
		return subprocess.run(["sudo", "cat", path], capture_output=True).stdout.decode()

def get_libs(mapfile: str) -> list[str]:
	# file structure is:
	# address perms offset dev inode pathname
	# pathname can be blank, for mmap()'d memory
 
	maps = [m.split() for m in mapfile.splitlines()]
	maps = [m for m in maps if len(m) == 6] # filter out mmap()'d memory
	libs = [m[5] for m in maps if not m[5].startswith('[')] # filter out [stack], [heap], [vdso], etc.
	libs = list(dict.fromkeys(libs)) # remove duplicates
	libs = libs[1:] # remove the executable itself (i hope this always works..)

	return libs

def parse_mountinfo(raw: str) -> dict[str, str]:
	mounts = [m.split() for m in raw.splitlines(False)]
	mappings = {m[4]: m[3] for m in mounts}
	return mappings

def find_container_by_port(client: docker.DockerClient, port: int) -> docker.models.containers.Container:
	containers: list[docker.models.containers.Container] = client.containers.list()
	return next((c for c in containers if any(int(port_proto.split('/')[0]) == port for port_proto in c.ports)), None)

def get_container(client: docker.DockerClient, args: argparse.Namespace) -> docker.models.containers.Container:
	is_compose = "docker-compose.yml" in os.listdir()
	is_dockerfile = "Dockerfile" in os.listdir()

	if not is_compose and not is_dockerfile:
		print("No docker setup found; checking for live container")
		container = find_container_by_port(client, args.port)
		if container is None:
			print("Error: no live container found")
			exit(1)
		
		return container
	
	try:
		if is_compose:
			print("Detected docker-compose.yml")
			container_id = build_from_compose()
		elif is_dockerfile:
			print("Building Dockerfile")
			container_id = build_from_dockerfile(client, args)
	
		container = client.containers.get(container_id)
		atexit.register(lambda: container.kill())
		print("Registered an atexit container killer")
	except docker.errors.APIError as err:
		if not err.is_server_error():
			raise err
		elif "bind: address already in use" in err.explanation:
			print("Error: target port is already in use, most likely not by a container")
			exit(1)
		elif "port is already allocated" not in err.explanation:
			raise err
		
		print("Error: the target port is already allocated; finding target container")
		container = find_container_by_port(client, args.port)
		if container is None:
			print("Error: port is already allocated by a container, but it can't found")
			exit(1)
	
	return container

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-p", "--port", help="Port to expose and connect to", type=int, required=True)
	parser.add_argument("--privileged", help="Run the container as privileged", action="store_true")
	parser.add_argument("--no-proc-heuristics", help="Disable usage of heuristics to determine the target process if unsure", action="store_true")
	args = parser.parse_args()

	client = docker.from_env()
	container = get_container(client, args)
	print(f"Container: {container.id}")

	before = get_procs(container)
	print(f"PIDs before connecting: {[proc.pid for proc in before]}")

	sleep_ms = 50
	print(f"Sleeping for {sleep_ms}ms to allow the container to start")
	time.sleep(sleep_ms / 1000)

	print(f"Connecting to localhost:{args.port}")
	sock = socket.socket()
	sock.connect(("localhost", args.port))

	# Wait for the target process to start completely
	# Initially, this PID will be of the jail/socat/whatever process after it's fork()'ed
	# We want to wait for it to execve() our program before reading its maps, or we'll get the wrong libs
	sleep_ms = 50
	print(f"Sleeping for {sleep_ms}ms to allow the process to start completely")
	time.sleep(sleep_ms / 1000)

	after = get_procs(container)
	print(f"PIDs after connecting: {[proc.pid for proc in after]}")

	target_proc = choose_proc(before, after, args)

	print("Reading process maps")
	maps = read_super(f"/proc/{target_proc.pid}/maps")
	libraries = get_libs(maps)
	lib_names = [lib.split('/')[-1] for lib in libraries]
	print(f"Libraries: {lib_names}")

	print("Checking for chroot")
	mountinfo = read_super(f"/proc/{target_proc.pid}/mountinfo")
	chroot = parse_mountinfo(mountinfo).get('/')
	if chroot:
		print(f"Detected chroot at {chroot}; fixing library paths")
		libraries = [chroot+path for path in libraries]

	print("Copying libraries")
	for name, path in zip(lib_names, libraries):
		print(f"Copying {path}")

		bits, stat = container.get_archive(path)
		with open(name, "wb") as f:
			for chunk in bits:
				f.write(chunk)
		
		# Unpack the tarball
		os.system(f"tar -xf {name}")
		
		# Set the same permissions as the original file
		os.chmod(name, stat["mode"])

if __name__ == "__main__":
	main()
