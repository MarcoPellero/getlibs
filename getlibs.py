#!/usr/bin/env python3

import docker
import argparse
import socket
import time
import os

class Process:
	def __init__(self, pid: int, cmd: str):
		self.pid = pid
		self.cmd = cmd
	
	def __repr__(self) -> str:
		cmd_str = self.cmd[:10]
		if len(self.cmd) > 10:
			cmd_str += "..."
		
		return f"Process(pid={self.pid}, cmd={cmd_str})"

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

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-p", "--port", help="Port to expose and connect to", type=int, required=True)
	parser.add_argument("--privileged", help="Run the container as privileged", action="store_true")
	args = parser.parse_args()

	if is_pwnred():
		args.privileged = True
		print("Detected pwn.red/jail Dockerfile, running as privileged")

	client = docker.from_env()

	img, _ = client.images.build(path=".")
	print(f"Image: {img.id}")

	container = client.containers.run(img, detach=True, ports={args.port: args.port}, privileged=args.privileged)
	print(f"Container: {container.id}")

	before = get_pids(client, container.id)
	print(f"PIDs before connecting: {[proc.pid for proc in before]}")

	sleep_ms = 50
	print(f"Sleeping for {sleep_ms}ms to allow the container to start")
	time.sleep(sleep_ms / 1000)

	print(f"Connecting to localhost:{args.port}")
	sock = socket.socket()
	sock.connect(("localhost", args.port))

	after = get_pids(client, container.id)
	print(f"PIDs after connecting: {[proc.pid for proc in after]}")

	new_procs = list(set(after) - set(before))
	print(f"New PIDs: {[proc.pid for proc in new_procs]}")

	if len(new_procs) != 1:
		print("Error: Expected exactly one new process")
		target_pid = choose_pid(new_procs)
		if target_pid == -1:
			print("Stopping container")
			client.containers.get(container.id).stop()
			return
	else:
		target_pid = new_procs[0].pid
		print(f"Target PID: {target_pid}")

	# Wait for the target process to start completely
	# Initially, this PID will be of the jail/socat/whatever process after it's fork()'ed
	# We want to wait for it to execve() our program before reading its maps, or we'll get the wrong libs
	sleep_ms = 50
	print(f"Sleeping for {sleep_ms}ms to allow the process to start completely")
	time.sleep(sleep_ms / 1000)

	print("Reading process maps")
	with open(f"/proc/{target_pid}/maps") as f:
		maps = f.read()
	
	maps = maps.split('\n')
	map_names = list(set([m.split()[-1] for m in maps if m]))

	libraries = [m for m in map_names if "lib" in m]
	if is_pwnred():
		print("Detected pwn.red/jail Dockerfile, fixing library paths for its chroot at /srv/")
		libraries = [f"/srv{path}" for path in libraries]
	
	lib_names = [lib.split('/')[-1] for lib in libraries]
	print(f"Libraries: {lib_names}")

	print("Copying libraries")
	for name, path in zip(lib_names, libraries):
		print(f"Copying {path}")

		bits, stat = client.containers.get(container.id).get_archive(path)
		with open(name, "wb") as f:
			for chunk in bits:
				f.write(chunk)
		
		# Unpack the tarball
		os.system(f"tar -xf {name}")
		
		# Set the same permissions as the original file
		os.chmod(name, stat["mode"])

	print("Stopping container")
	client.containers.get(container.id).stop()

if __name__ == "__main__":
	main()
