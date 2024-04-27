#!/usr/bin/env python3

import docker
import argparse
import socket
import time
import os
import subprocess

class Process:
	def __init__(self, pid: int, cmd: str):
		self.pid = pid
		self.cmd = cmd
	
	def __repr__(self) -> str:
		cmd_str = self.cmd[:10]
		if len(self.cmd) > 10:
			cmd_str += "..."
		
		return f"Process(pid={self.pid}, cmd={cmd_str})"
	
	def __eq__(self, other: object) -> bool:
		return isinstance(other, Process) and self.pid == other.pid

	def __hash__(self):
		return self.pid

def get_pids(client: docker.DockerClient, container_id: str) -> list[Process]:
	top = client.containers.get(container_id).top()
	processes = top["Processes"]
	pid_idx, cmd_idx = 1, -1
	return [Process(int(proc[pid_idx]), proc[cmd_idx]) for proc in processes]

def is_pwnred() -> bool:
	if os.path.exists("./Dockerfile"):
		with open("./Dockerfile") as f:
			return "FROM pwn.red/jail" in f.read()
	
	return False

def choose_pid(procs: list[Process]) -> int:
	print("Multiple new processes detected, please choose the target PID:")
	for i, proc in enumerate(procs):
		print(f"\t{proc.pid}: {proc.cmd}")
	
	print("\t-1: Stop the container")
	pid = int(input("PID: "))
	if pid != -1 and pid not in map(lambda p: p.pid, procs):
		print("Invalid PID; stopping the container")
		pid = -1
	
	return pid

def build_from_compose() -> str:
	subprocess.run(["docker", "compose", "up", "--build", "-d"])
	result = subprocess.run(["docker", "compose", "ps", "-q"], capture_output=True)
	return result.stdout.decode().strip()

def build_from_dockerfile(client: docker.DockerClient, args: argparse.Namespace) -> str:
	if is_pwnred():
		args.privileged = True
		print("Detected pwn.red/jail Dockerfile, running as privileged")
	
	img, _ = client.images.build(path=".")
	print(f"Image: {img.id}")

	container = client.containers.run(img, detach=True, ports={args.port: args.port}, privileged=args.privileged)
	return container.id

def get_libs(mapfile: str) -> list[str]:
	# file structure is:
	# address perms offset dev inode pathname
	# pathname can be blank, for mmap()'d memory
 
	maps = [m.split() for m in mapfile.split('\n')]
	maps = [m for m in maps if len(m) == 6] # filter out mmap()'d memory
	libs = [m[5] for m in maps if not m[5].startswith('[')] # filter out [stack], [heap], [vdso], etc.
	libs = list(dict.fromkeys(libs)) # remove duplicates
	libs = libs[1:] # remove the executable itself (i hope this always works..)

	return libs

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
		container_id = build_from_dockerfile(client, args)

	print(f"Container: {container_id}")

	before = get_pids(client, container_id)
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

	after = get_pids(client, container_id)
	print(f"PIDs after connecting: {[proc.pid for proc in after]}")

	new_procs = list(set(after) - set(before))
	print(f"New PIDs: {[proc.pid for proc in new_procs]}")

	if len(new_procs) != 1:
		print("Error: Expected exactly one new process")
		target_pid = choose_pid(new_procs)
		if target_pid == -1:
			print("Stopping container")
			client.containers.get(container_id).stop()
			return
	else:
		proc = new_procs[0]
		target_pid = proc.pid
		print(f"Target PID: {target_pid} ({proc.cmd})")

	print("Reading process maps")
	try:
		with open(f"/proc/{target_pid}/maps") as f:
			maps = f.read()
	except PermissionError:
		print("Error: Permission denied; trying again with sudo")
		maps = subprocess.run(["sudo", "cat", f"/proc/{target_pid}/maps"], capture_output=True).stdout.decode()
	
	libraries = get_libs(maps)
	lib_names = [lib.split('/')[-1] for lib in libraries]
	print(f"Libraries: {lib_names}")

	if is_pwnred():
		print("Detected pwn.red/jail Dockerfile, fixing library paths for its chroot at /srv/")
		libraries = [f"/srv{path}" for path in libraries]

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
