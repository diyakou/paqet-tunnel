#!/usr/bin/env bash
set -euo pipefail

APP_NAME="licensebot"
INSTALL_DIR="/opt/licensebot"
DATA_DIR="${INSTALL_DIR}/data"
ENV_FILE="${INSTALL_DIR}/licensebot.env"
BIN_PATH="${INSTALL_DIR}/licensebot"
SERVICE_PATH="/etc/systemd/system/licensebot.service"

ADMIN_CHAT_ID_DEFAULT="1879326595"
HTTP_ADDR_DEFAULT=":8080"
DB_PATH_DEFAULT="${DATA_DIR}/licensebot.db"

GO_VERSION_DEFAULT="1.23.0"
REPO_URL_DEFAULT=""
BRANCH_DEFAULT="main"

usage() {
	cat <<EOF
Usage:
  sudo ./install.sh [options]

Options:
  --bot-token <token>          Telegram bot token (or env BOT_TOKEN)
  --admin-chat-id <id>         Admin chat id (default: ${ADMIN_CHAT_ID_DEFAULT})
  --http-addr <addr>           HTTP listen addr (default: ${HTTP_ADDR_DEFAULT})
  --db-path <path>             DB path (default: ${DB_PATH_DEFAULT})

  --repo <git_url>             (Optional) clone source from repo if not running inside source dir
  --branch <name>              (Optional) repo branch (default: ${BRANCH_DEFAULT})

  --go-version <ver>           Install Go version if needed (default: ${GO_VERSION_DEFAULT})
  --no-go-install              Don't auto-install Go (fail if Go missing)
  --force-env                  Overwrite ${ENV_FILE} if it exists

Examples:
  sudo ./install.sh --bot-token "123:ABC" \
    --admin-chat-id 1879326595 --http-addr ":8080"
EOF
}

need_root() {
	if [[ "${EUID}" -ne 0 ]]; then
		echo "ERROR: run as root (sudo)" >&2
		exit 1
	fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

install_pkgs() {
	# minimal deps: curl, ca-certificates, tar, git (only if repo clone needed)
	if have_cmd apt-get; then
		DEBIAN_FRONTEND=noninteractive apt-get update -y
		DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates tar
		return
	fi
	if have_cmd dnf; then
		dnf install -y curl ca-certificates tar
		return
	fi
	if have_cmd yum; then
		yum install -y curl ca-certificates tar
		return
	fi
	if have_cmd pacman; then
		pacman -Sy --noconfirm curl ca-certificates tar
		return
	fi
}

ensure_systemd() {
	if ! have_cmd systemctl; then
		echo "ERROR: systemd/systemctl not found on this server" >&2
		exit 1
	fi
}

ensure_user() {
	if id -u ${APP_NAME} >/dev/null 2>&1; then
		return
	fi
	useradd --system --home "${INSTALL_DIR}" --shell /usr/sbin/nologin ${APP_NAME}
}

go_install_if_needed() {
	local no_install="$1"
	local go_version="$2"

	local need_install=0
	if have_cmd go; then
		local current
		current="$(go env GOVERSION 2>/dev/null || true)"
		# current like: go1.21.6
		if [[ "${current}" =~ ^go([0-9]+)\.([0-9]+) ]]; then
			local cur_major="${BASH_REMATCH[1]}"
			local cur_minor="${BASH_REMATCH[2]}"
			local req_major req_minor
			req_major="${go_version%%.*}"
			req_minor="${go_version#*.}"
			req_minor="${req_minor%%.*}"
			if (( cur_major < req_major )) || (( cur_major == req_major && cur_minor < req_minor )); then
				need_install=1
			fi
		else
			# Unknown format; install known Go.
			need_install=1
		fi
	else
		need_install=1
	fi

	if [[ "${need_install}" -eq 0 ]]; then
		return
	fi
	if [[ "${no_install}" == "1" ]]; then
		echo "ERROR: Go not found and --no-go-install was set" >&2
		exit 1
	fi

	echo "Go not found; installing Go ${go_version} to /usr/local/go ..."
	install_pkgs || true

	local arch
	arch="$(uname -m)"
	case "${arch}" in
		x86_64|amd64) arch="amd64";;
		aarch64|arm64) arch="arm64";;
		*) echo "ERROR: unsupported arch: ${arch}" >&2; exit 1;;
	esac

	local url="https://go.dev/dl/go${go_version}.linux-${arch}.tar.gz"
	rm -rf /usr/local/go
	curl -fsSL "${url}" -o /tmp/go.tgz
	tar -C /usr/local -xzf /tmp/go.tgz
	rm -f /tmp/go.tgz

	# Make available for this script execution.
	export PATH="/usr/local/go/bin:${PATH}"
	# Prevent go from attempting to auto-download a newer toolchain.
	export GOTOOLCHAIN=local

	# Persist PATH for shells (best-effort).
	if [[ -f /etc/profile ]]; then
		grep -q '/usr/local/go/bin' /etc/profile || echo 'export PATH=/usr/local/go/bin:$PATH' >> /etc/profile
	fi
}

resolve_source_dir() {
	local repo_url="$1"
	local branch="$2"

	# If running inside the source dir, use it.
	if [[ -d "./cmd/licensebot" && -f "./cmd/licensebot/main.go" ]]; then
		echo "$(pwd)"
		return
	fi

	if [[ -z "${repo_url}" ]]; then
		echo "ERROR: not running inside source dir and --repo was not provided" >&2
		exit 1
	fi

	install_pkgs || true
	if ! have_cmd git; then
		if have_cmd apt-get; then
			DEBIAN_FRONTEND=noninteractive apt-get install -y git
		elif have_cmd dnf; then
			dnf install -y git
		elif have_cmd yum; then
			yum install -y git
		elif have_cmd pacman; then
			pacman -Sy --noconfirm git
		else
			echo "ERROR: git missing and package manager not detected" >&2
			exit 1
		fi
	fi

	mkdir -p "${INSTALL_DIR}"
	if [[ -d "${INSTALL_DIR}/src/.git" ]]; then
		cd "${INSTALL_DIR}/src"
		git fetch --all --prune
		git checkout "${branch}"
		git pull --ff-only
		echo "${INSTALL_DIR}/src"
		return
	fi

	rm -rf "${INSTALL_DIR}/src"
	git clone --depth 1 --branch "${branch}" "${repo_url}" "${INSTALL_DIR}/src"
	echo "${INSTALL_DIR}/src"
}

write_env_file() {
	local bot_token="$1"
	local admin_chat_id="$2"
	local http_addr="$3"
	local db_path="$4"
	local force_env="$5"

	mkdir -p "${INSTALL_DIR}" "${DATA_DIR}"

	if [[ -f "${ENV_FILE}" && "${force_env}" != "1" ]]; then
		echo "Env exists: ${ENV_FILE} (use --force-env to overwrite)"
		return
	fi

	cat >"${ENV_FILE}" <<EOF
BOT_TOKEN=${bot_token}
ADMIN_CHAT_ID=${admin_chat_id}
HTTP_ADDR=${http_addr}
DB_PATH=${db_path}
EOF
	chmod 600 "${ENV_FILE}"
}

install_service() {
	cat >"${SERVICE_PATH}" <<EOF
[Unit]
Description=KYPAQET License Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${APP_NAME}
Group=${APP_NAME}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${BIN_PATH}
Restart=always
RestartSec=2

EnvironmentFile=${ENV_FILE}

NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

	systemctl daemon-reload
	systemctl enable --now licensebot
}

main() {
	need_root
	ensure_systemd

	local bot_token="${BOT_TOKEN:-}"
	local admin_chat_id="${ADMIN_CHAT_ID:-${ADMIN_CHAT_ID_DEFAULT}}"
	local http_addr="${HTTP_ADDR:-${HTTP_ADDR_DEFAULT}}"
	local db_path="${DB_PATH:-${DB_PATH_DEFAULT}}"
	local repo_url="${REPO_URL:-${REPO_URL_DEFAULT}}"
	local branch="${BRANCH:-${BRANCH_DEFAULT}}"
	local go_version="${GO_VERSION:-${GO_VERSION_DEFAULT}}"
	local no_go_install=0
	local force_env=0

	while [[ $# -gt 0 ]]; do
		case "$1" in
			--bot-token) bot_token="$2"; shift 2;;
			--admin-chat-id) admin_chat_id="$2"; shift 2;;
			--http-addr) http_addr="$2"; shift 2;;
			--db-path) db_path="$2"; shift 2;;
			--repo) repo_url="$2"; shift 2;;
			--branch) branch="$2"; shift 2;;
			--go-version) go_version="$2"; shift 2;;
			--no-go-install) no_go_install=1; shift 1;;
			--force-env) force_env=1; shift 1;;
			-h|--help) usage; exit 0;;
			*) echo "Unknown option: $1" >&2; usage; exit 1;;
		esac
	done

	if [[ -z "${bot_token}" ]]; then
		echo "ERROR: bot token missing. Provide --bot-token or env BOT_TOKEN" >&2
		exit 1
	fi

	ensure_user
	mkdir -p "${INSTALL_DIR}" "${DATA_DIR}"
	chown -R ${APP_NAME}:${APP_NAME} "${INSTALL_DIR}"

	go_install_if_needed "${no_go_install}" "${go_version}"
	# Prefer the installer-managed Go if present.
	if [[ -x /usr/local/go/bin/go ]]; then
		export PATH="/usr/local/go/bin:${PATH}"
	fi

	local src_dir
	src_dir="$(resolve_source_dir "${repo_url}" "${branch}")"

	# Build binary
	if have_cmd go; then
		:
	else
		export PATH="/usr/local/go/bin:${PATH}"
	fi
	# Never auto-download toolchains during install.
	export GOTOOLCHAIN=local
	cd "${src_dir}"
	go build -o "${BIN_PATH}" ./cmd/licensebot
	chown ${APP_NAME}:${APP_NAME} "${BIN_PATH}"
	chmod 755 "${BIN_PATH}"

	write_env_file "${bot_token}" "${admin_chat_id}" "${http_addr}" "${db_path}" "${force_env}"
	chown ${APP_NAME}:${APP_NAME} "${ENV_FILE}"

	install_service

	echo "OK: installed and started."
	systemctl --no-pager status licensebot || true
}

main "$@"
