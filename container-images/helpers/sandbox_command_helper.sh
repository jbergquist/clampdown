# SPDX-License-Identifier: GPL-3.0-only
# Sourced via BASH_ENV in agent containers.
#
# Point-of-failure guidance for sandbox errors. Shell functions intercept
# installed commands that will fail due to sandbox restrictions. Commands
# that are not installed are handled by command_not_found_handle instead.
#
# Per-tool hints print the exact podman run command with the right image
# and env var overrides for read-only rootfs (from LIST.md).
# Images use Alpine variants where available for smaller pulls.

# Per-session cache dir set by the launcher. Env vars in container commands
# point caches here so they land on the writable workdir, not the read-only rootfs.
S="${SANDBOX_CACHE:-$HOME}"

# Print a ready-to-copy podman run command for a known tool.
# Usage: _run_hint IMAGE COMMAND [-e KEY=VAL ...]
_run_hint()
{
	local img="${1}" cmd="${2}"
	shift 2
	local envs=""
	while [ $# -gt 0 ]; do envs="${envs} -e ${1}"; shift; done
	echo "'${cmd}' is not installed. Run in a container:
    podman run -v \"\$PWD\":\"\$PWD\" -w \"\$PWD\" -e HOME=\"${S}\"${envs} ${img} ${cmd} [ARGS]
Resolve the image digest before running (podman pull + podman image inspect --format '{{.Digest}}')."
	return 2
}

# Print a build-your-own hint for tools that need a custom image.
# Usage: _build_hint COMMAND PACKAGE
_build_hint()
{
	echo "'${1}' is not installed. Build an image, then run it:
    printf 'FROM alpine:3.21\nRUN apk add --no-cache ${2}\n' | podman build -t ${1} -
    podman run -v \"\$PWD\":\"\$PWD\" -w \"\$PWD\" -e HOME=\"${S}\" ${1} ${1} [ARGS]"
	return 2
}

command_not_found_handle()
{
	case "${1}" in
	# --- Go ---
	go)
		_run_hint golang:alpine go \
			"GOPATH=${S}/go" \
			"GOCACHE=${S}/go-build" \
			"GOMODCACHE=${S}/go/pkg/mod"
		;;
	# --- Rust ---
	cargo|rustc|rustup)
		_run_hint rust "${1}" \
			"CARGO_HOME=${S}/cargo"
		;;
	# --- Python ---
	python|python3|pip|pip3)
		_run_hint python:alpine "${1}" \
			"PIP_CACHE_DIR=${S}/pip-cache" \
			"PYTHONUSERBASE=${S}/python"
		;;
	# --- Node.js ---
	node|npm|npx)
		_run_hint node:alpine "${1}" \
			"npm_config_cache=${S}/npm-cache" \
			"COREPACK_HOME=${S}/corepack"
		;;
	# --- C / C++ / Fortran / build tools ---
	gcc|g++|cc|c++|gfortran|make|cmake|ar|strip|ldd|objdump)
		_run_hint gcc "${1}"
		;;
	# --- Ruby ---
	ruby|gem|bundle|bundler)
		_run_hint ruby:alpine "${1}" \
			"GEM_HOME=${S}/gems" \
			"BUNDLE_PATH=${S}/bundle" \
			"GEM_SPEC_CACHE=${S}/gem-specs"
		;;
	# --- Java / Kotlin / Scala ---
	javac|java|gradle|mvn)
		_run_hint eclipse-temurin "${1}" \
			"JAVA_TOOL_OPTIONS=-Duser.home=${S}" \
			"GRADLE_USER_HOME=${S}/gradle"
		;;
	sbt)
		_run_hint eclipse-temurin sbt \
			"JAVA_TOOL_OPTIONS=-Duser.home=${S}" \
			"SBT_OPTS=-Dsbt.global.base=${S}/sbt -Dsbt.boot.directory=${S}/sbt/boot -Dsbt.ivy.home=${S}/ivy2" \
			"COURSIER_CACHE=${S}/coursier"
		;;
	# --- .NET ---
	dotnet)
		_run_hint mcr.microsoft.com/dotnet/sdk dotnet \
			"DOTNET_CLI_HOME=${S}/dotnet" \
			"NUGET_PACKAGES=${S}/nuget" \
			"DOTNET_CLI_TELEMETRY_OPTOUT=1"
		;;
	# --- Swift ---
	swift)
		_run_hint swift swift
		;;
	# --- Haskell ---
	ghc|cabal|stack)
		_run_hint haskell "${1}" \
			"CABAL_DIR=${S}/cabal" \
			"STACK_ROOT=${S}/stack"
		;;
	# --- Elixir ---
	mix|elixir|iex)
		_run_hint elixir:alpine "${1}" \
			"MIX_HOME=${S}/mix" \
			"HEX_HOME=${S}/hex" \
			"REBAR_CACHE_DIR=${S}/rebar"
		;;
	# --- Clojure ---
	clojure|lein)
		_run_hint clojure "${1}" \
			"JAVA_TOOL_OPTIONS=-Duser.home=${S}" \
			"LEIN_HOME=${S}/lein" \
			"CLJ_CONFIG=${S}/clojure"
		;;
	# --- Dart ---
	dart|pub)
		_run_hint dart "${1}" \
			"PUB_CACHE=${S}/pub-cache"
		;;
	# --- Julia ---
	julia)
		_run_hint julia julia \
			"JULIA_DEPOT_PATH=${S}/julia:"
		;;
	# --- Nim ---
	nim|nimble)
		_run_hint nimlang/nim "${1}" \
			"NIMBLE_DIR=${S}/nimble"
		;;
	# --- R ---
	R|Rscript)
		_run_hint r-base "${1}" \
			"R_LIBS_USER=${S}/R/library"
		;;
	# --- PHP ---
	php|composer)
		_run_hint php:alpine "${1}" \
			"COMPOSER_HOME=${S}/composer" \
			"COMPOSER_CACHE_DIR=${S}/composer/cache"
		;;
	# --- Perl ---
	perl|cpanm)
		_run_hint perl:slim "${1}" \
			"PERL_CPANM_HOME=${S}/cpanm" \
			"PERL5LIB=${S}/perl5/lib/perl5"
		;;
	# --- Git ---
	git)
		_run_hint alpine/git git
		;;
	# --- GitHub CLI ---
	gh)
		_build_hint gh github-cli
		;;
	# --- Groovy ---
	groovy)
		_run_hint groovy groovy \
			"JAVA_TOOL_OPTIONS=-Duser.home=${S} -Dgrape.root=${S}/groovy" \
			"GRADLE_USER_HOME=${S}/gradle"
		;;
	# --- Octave ---
	octave)
		_run_hint gnuoctave/octave octave
		;;
	# --- Unknown tool: generic message ---
	*)
		echo "'${1}' is not installed. Re-run the command in a container.
Do not check paths, alternatives, or install methods.
    podman run -v \"\$PWD\":\"\$PWD\" -w \"\$PWD\" IMAGE COMMAND [ARGS]
Host credentials (git, gh, ssh, registry auth) are forwarded into containers automatically by the sandbox.
If not found, prompt the user about them, don't try to configure auth, mount credential files, or set tokens manually.
Common images: python:alpine, golang:alpine, gcc, rust, ruby:alpine, node:alpine, php:alpine, perl:slim, alpine/git.
For tools not in common images, build one:
    printf 'FROM alpine:3.21\nRUN apk add --no-cache PKG\n' | podman build -t name -"
		return 2
		;;
	esac
}

curl()
{
	echo "curl: your process is firewalled to approved API domains only.
Containers have open internet. Run curl in a container:
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
	echo "su: not available. This container has no root access (cap-drop=ALL)."
	return 2
}

sudo()
{
	echo "sudo: not available. This container has no root access (cap-drop=ALL)."
	return 2
}

# Package managers — rootfs is read-only, none of these can install packages.
_pkg_blocked()
{
	echo "${1}: the rootfs is read-only — packages cannot be installed natively.
Build an image with the packages you need:
    printf 'FROM alpine:3.21\nRUN apk add --no-cache PKG\n' | podman build -t name -"
	return 2
}

apk()     { _pkg_blocked apk; }
apt()     { _pkg_blocked apt; }
apt-get() { _pkg_blocked apt-get; }
yum()     { _pkg_blocked yum; }
dnf()     { _pkg_blocked dnf; }
brew()    { _pkg_blocked brew; }
pacman()  { _pkg_blocked pacman; }
