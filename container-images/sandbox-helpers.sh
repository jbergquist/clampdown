# SPDX-License-Identifier: GPL-3.0-only
# Sourced via BASH_ENV in agent containers.
#
# Point-of-failure guidance for sandbox errors. Shell functions intercept
# installed commands that will fail due to sandbox restrictions. Commands
# that are not installed are handled by command_not_found_handle instead.

command_not_found_handle()
{
	echo "'${1}' is not installed. Re-run the command in a container.
Do not check paths, alternatives, or install methods.
    podman run -v \"\$PWD\":\"\$PWD\" -w \"\$PWD\" IMAGE COMMAND [ARGS]
Host credentials (git, gh, ssh, registry auth) are forwarded into containers automatically by the sandbox.
If not found, prompt the user about them, don't try to configure auth, mount credential files, or set tokens manually.
Common images: python, golang, gcc, rust, ruby, node, php, perl, alpine/git.
For tools not in common images, build one:
    printf 'FROM alpine:3.21\nRUN apk add --no-cache PKG\n' | podman build -t name -"
	return 2
}

curl()
{
	echo "curl: your process is firewalled to approved API domains only.
Containers have open internet. Run wget in a container:
    podman run -v \"\$PWD\":\"\$PWD\" -w \"\$PWD\" alpine@sha256:<digest> curl \"\$@\""
	return 2
}

wget()
{
	echo "wget: your process is firewalled to approved API domains only.
Containers have open internet. Run wget in a container:
    podman run -v \"\$PWD\":\"\$PWD\" -w \"\$PWD\" alpine@sha256:<digest> wget \"\$@\""
	return 2
}

ping()
{
	echo "ping: your process is firewalled. ICMP is blocked by seccomp.
Use a container to test connectivity:
    podman run alpine@sha256:<digest> ping \"\$@\""
	return 2
}

su()
{
	echo "su: not available. This container has no root access (cap-drop=ALL).
If you need root for a command, run it in a container (root inside its own namespace):
    podman run -v \"\$PWD\":\"\$PWD\" -w \"\$PWD\" IMAGE COMMAND"
	return 2
}

apk()
{
	echo "apk: the rootfs is read-only — packages cannot be installed natively.
Build an image with the packages you need:
    printf 'FROM alpine:3.21\nRUN apk add --no-cache PKG\n' | podman build -t name -"
	return 2
}
