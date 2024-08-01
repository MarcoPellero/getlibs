#!/usr/bin/env python3

import docker
import argparse
import socket
import time
import os
import subprocess
import psutil

def get_procs(client: docker.DockerClient, container_id: str) -> list[psutil.Process]:
	top = client.containers.get(container_id).top()
	procs = top["Processes"]
	pids = [int(proc[1]) for proc in procs]
	return [psutil.Process(pid) for pid in pids]

def choose_proc(procs: list[psutil.Process]) -> psutil.Process:
	print("Multiple new processes detected, please choose the target PID:")
	print("\t-1: Stop the container")
	for proc in procs:
		print(f"\t{proc.pid}: {' '.join(proc.cmdline())}")

	pid = int(input("PID: "))
	if pid == -1:
		return None

	proc = next((proc for proc in procs if proc.pid == pid), None)
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

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-p", "--port", help="Port to expose and connect to", type=int, required=True)
	parser.add_argument("--privileged", help="Run the container as privileged", action="store_true")
	args = parser.parse_args()

	client = docker.from_env()
	container_id = ""
	if "docker-compose.yml" in os.listdir():
		print("Detected docker-compose.yml")
		container_id = build_from_compose()
	else:
		print("Building Dockerfile")
		container_id = build_from_dockerfile(client, args)

	print(f"Container: {container_id}")

	before = get_procs(client, container_id)
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

	after = get_procs(client, container_id)
	print(f"PIDs after connecting: {[proc.pid for proc in after]}")

	new_procs = list(set(after) - set(before))
	print(f"New PIDs: {[proc.pid for proc in new_procs]}")

	if len(new_procs) != 1:
		print("Error: Expected exactly one new process")
		target_proc = choose_proc(new_procs)
		if target_proc is None:
			print("Stopping container")
			client.containers.get(container_id).stop()
			return
	else:
		target_proc = new_procs[0]
		print(f"Target process: PID={target_proc.pid}; CMD=({' '.join(target_proc.cmdline())})")

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
		libraries = [f"{chroot}/{path}" for path in libraries]

	print("Copying libraries")
	for name, path in zip(lib_names, libraries):
		print(f"Copying {path}")

		bits, stat = client.containers.get(container_id).get_archive(path)
		with open(name, "wb") as f:
			for chunk in bits:
				f.write(chunk)
		
		# Unpack the tarball
		os.system(f"tar -xf {name}")
		
		# Set the same permissions as the original file
		os.chmod(name, stat["mode"])

	print("Stopping container")
	client.containers.get(container_id).kill()

if __name__ == "__main__":
	main()
