#!/bin/bash

# Paqet Direct Tunnel Deployment Script for Linux
# Configures paqet for direct tunnel between Iran (client) and Kharej (server)
# Supports multiple tunnels (multiple servers from 1 client, or multiple clients to 1 server)
# Usage: sudo ./deploy.sh
# The script will ask you if you're setting up a client or server

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
DIM='\033[2m'
NC='\033[0m' # No Color

# UI glyphs / emojis
ICON_OK="✅"
ICON_ERR="❌"
ICON_WARN="⚠️"
ICON_INFO="ℹ️"
ICON_MENU="🧭"
ICON_DEPLOY="🚀"
ICON_GEAR="⚙️"
ICON_LOGS="📜"
ICON_TUNNEL="🛰️"
ICON_SHIELD="🛡️"
ICON_BACK="↩️"
ICON_EXIT="🚪"

# Global arrays for multiple tunnel support
declare -a TUNNEL_CONFIGS
declare -a TUNNEL_NAMES
declare -a TUNNEL_SERVERS
declare -a TUNNEL_PORTS
declare -a TUNNEL_KEYS
declare -a TUNNEL_FORWARD_RULES
declare -a INTERFACE_IPV4S

# Functions for output
ui_line() {
    local _char="${1:-=}"
    local count="${2:-48}"
    printf '%*s\n' "$count" '' | tr ' ' '='
}

print_header() {
    echo ""
    echo -e "${CYAN}"
    ui_line "═" 56
    echo -e "${WHITE}${ICON_MENU}  $1${NC}"
    echo -e "${CYAN}"
    ui_line "═" 56
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}${ICON_OK}  $1${NC}"
}

print_error() {
    echo -e "${RED}${ICON_ERR}  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}${ICON_WARN}  $1${NC}"
}

print_info() {
    echo -e "${BLUE}${ICON_INFO}  $1${NC}"
}

render_kypaqet_banner() {
    echo -e "${CYAN}"
    ui_line "=" 68
    echo -e "${WHITE} _  ___   __   _____  ___   ___ _____${NC}"
    echo -e "${WHITE}| |/ / | / /  / / _ \\/ _ | / _ \\_   _|${NC}"
    echo -e "${WHITE}| ' /| |/ /  / / ___/ __ |/ // / | |${NC}"
    echo -e "${WHITE}|_|\\_\\|___/  /_/_/  /_/ |_|____/  |_|${NC}"
    echo -e "${GREEN}KYPAQET${NC}"
    echo -e "${YELLOW}telegram : Exchi${NC}"
    ui_line "=" 68
    echo -e "${NC}"
}

# KCP manual preset defaults (role-aware)
set_kcp_defaults() {
    local role="$1"
    KCP_NODELAY=1
    KCP_INTERVAL=20
    KCP_RESEND=2
    KCP_NC=1
    KCP_SMUXBUF=4194304
    KCP_STREAMBUF=2097152
    if [ "$role" = "server" ]; then
        KCP_RCVWND=4096
        KCP_SNDWND=4096
    else
        KCP_RCVWND=2048
        KCP_SNDWND=2048
    fi
}

apply_kcp_mode_defaults() {
    local role="$1"
    local mode="$2"

    case "$mode" in
        fast2)
            # High speed with lower overhead than fast3.
            KCP_NODELAY=1
            KCP_INTERVAL=20
            KCP_RESEND=2
            KCP_NC=1
            if [ "$role" = "server" ]; then
                KCP_RCVWND=4096
                KCP_SNDWND=4096
            else
                KCP_RCVWND=2048
                KCP_SNDWND=2048
            fi
            KCP_SMUXBUF=4194304
            KCP_STREAMBUF=2097152
            ;;
        fast3)
            KCP_NODELAY=1
            KCP_INTERVAL=10
            KCP_RESEND=2
            KCP_NC=1
            if [ "$role" = "server" ]; then
                KCP_RCVWND=4096
                KCP_SNDWND=4096
            else
                KCP_RCVWND=2048
                KCP_SNDWND=2048
            fi
            KCP_SMUXBUF=8388608
            KCP_STREAMBUF=4194304
            ;;
        fast|*)
            KCP_NODELAY=0
            KCP_INTERVAL=30
            KCP_RESEND=2
            KCP_NC=1
            if [ "$role" = "server" ]; then
                KCP_RCVWND=4096
                KCP_SNDWND=4096
            else
                KCP_RCVWND=2048
                KCP_SNDWND=2048
            fi
            KCP_SMUXBUF=4194304
            KCP_STREAMBUF=2097152
            ;;
    esac
}

apply_kcp_preset() {
    local preset="$1"
    local role="$2"
    set_kcp_defaults "$role"

    case "$preset" in
        gaming)
            KCP_NODELAY=1
            KCP_INTERVAL=10
            KCP_RESEND=2
            KCP_NC=1
            if [ "$role" = "server" ]; then
                KCP_RCVWND=1024
                KCP_SNDWND=1024
            else
                KCP_RCVWND=512
                KCP_SNDWND=512
            fi
            KCP_SMUXBUF=2097152
            KCP_STREAMBUF=1048576
            ;;
        streaming)
            KCP_NODELAY=1
            KCP_INTERVAL=10
            KCP_RESEND=2
            KCP_NC=1
            if [ "$role" = "server" ]; then
                KCP_RCVWND=4096
                KCP_SNDWND=4096
            else
                KCP_RCVWND=2048
                KCP_SNDWND=2048
            fi
            KCP_SMUXBUF=8388608
            KCP_STREAMBUF=4194304
            ;;
        normal|*)
            set_kcp_defaults "$role"
            ;;
    esac
}

# Detect if a path is the deployment script (not the paqet binary)
is_script_paqet() {
    local path="$1"
    [ -f "$path" ] || return 1
    local first_line
    first_line=$(head -n 1 "$path" 2>/dev/null)
    if [[ "$first_line" == "#!/bin/bash"* ]] && grep -q "Paqet Direct Tunnel Deployment Script" "$path" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Resolve the real paqet binary (not the deployment script)
resolve_paqet_binary() {
    if [ -f "$PAQET_PATH/paqet" ] && ! is_script_paqet "$PAQET_PATH/paqet"; then
        echo "$PAQET_PATH/paqet"
        return 0
    fi
    if command -v paqet &> /dev/null; then
        local candidate
        candidate=$(command -v paqet)
        if ! is_script_paqet "$candidate"; then
            echo "$candidate"
            return 0
        fi
    fi
    return 1
}

# Get latest paqet release tag from GitHub API
get_latest_paqet_version() {
    local repo="diyakou/paqet"
    local api_url="https://api.github.com/repos/${repo}/releases/latest"
    local version=""

    if command -v gh &> /dev/null; then
        if gh auth status -t -h github.com >/dev/null 2>&1; then
            version=$(gh release view --repo "$repo" --json tagName -q .tagName 2>/dev/null | head -1)
        fi
    fi

    if [ -z "$version" ]; then
        if command -v curl &> /dev/null; then
            version=$(curl -fsSL "$api_url" 2>/dev/null | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
        elif command -v wget &> /dev/null; then
            version=$(wget -qO- "$api_url" 2>/dev/null | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
        fi
    fi

    echo "$version"
}

# Normalize a port value (handles ip:port input)
normalize_port() {
    local input="$1"
    input=$(echo "$input" | tr -d '[:space:]')
    if [[ "$input" == *:* ]]; then
        input="${input##*:}"
    fi
    input=$(echo "$input" | tr -cd '0-9')
    if [ -z "$input" ]; then
        echo ""
        return
    fi
    if [ "$input" -ge 1 ] && [ "$input" -le 65535 ]; then
        echo "$input"
    else
        echo ""
    fi
}

# Normalize host values for safe endpoint comparisons
normalize_host_for_compare() {
    local host="$1"
    host=$(echo "$host" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    host="${host#[}"
    host="${host%]}"
    case "$host" in
        ""|"localhost"|"0.0.0.0"|"::")
            echo "127.0.0.1"
            ;;
        *)
            echo "$host"
            ;;
    esac
}

# Validate forward rules and block self-referential tunnel loops
validate_forward_rules() {
    if [ "$MODE" != "client" ] || [ "$PROXY_TYPE" != "forward" ] || [ -z "$FORWARD_RULES" ]; then
        return 0
    fi

    local normalized_server_host
    local normalized_server_port
    normalized_server_host=$(normalize_host_for_compare "$SERVER_ADDRESS")
    normalized_server_port=$(normalize_port "$SERVER_PORT")

    if [ -z "$normalized_server_host" ] || [ -z "$normalized_server_port" ]; then
        return 0
    fi

    IFS=';' read -ra RULES <<< "$FORWARD_RULES"
    for rule in "${RULES[@]}"; do
        [ -z "$rule" ] && continue

        IFS=':' read -ra PARTS <<< "$rule"
        local local_port="${PARTS[0]}"
        local target_host="${PARTS[1]}"
        local target_port="${PARTS[2]}"

        local normalized_local_port
        local normalized_target_host
        local normalized_target_port
        normalized_local_port=$(normalize_port "$local_port")
        normalized_target_host=$(normalize_host_for_compare "$target_host")
        normalized_target_port=$(normalize_port "$target_port")

        if [ -z "$normalized_local_port" ] || [ -z "$normalized_target_host" ] || [ -z "$normalized_target_port" ]; then
            print_error "Invalid forward rule: $rule"
            print_info "Expected format: local_port:target_host:target_port[:protocol]"
            return 1
        fi

        if [ "$normalized_target_port" = "$normalized_server_port" ] && \
           { [ "$normalized_target_host" = "$normalized_server_host" ] || [ "$normalized_target_host" = "127.0.0.1" ] || [ "$normalized_target_host" = "::1" ]; }; then
            print_error "Unsafe forward rule detected: :$normalized_local_port -> $target_host:$normalized_target_port"
            print_error "This points to the paqet listener endpoint ($SERVER_ADDRESS:$SERVER_PORT) and can create a traffic loop."
            print_info "Use a different target service/port than the paqet server port."
            return 1
        fi
    done

    if [[ "$CONN_COUNT" =~ ^[0-9]+$ ]] && [ "$CONN_COUNT" -gt 10 ]; then
        print_warning "Connection count is $CONN_COUNT. High conn values increase bandwidth overhead."
        print_info "Use 3-5 connections for optimal performance with many users."
    fi

    return 0
}

# Select a single IPv4 address to bind/listen on (supports multi-IP interfaces)
select_local_ipv4() {
    if [ ${#INTERFACE_IPV4S[@]} -eq 0 ]; then
        print_error "No IPv4 addresses available on interface $INTERFACE"
        return 1
    fi

    # If a bind IP is provided via CLI, validate and use it directly.
    if [ -n "$BIND_IP" ]; then
        for ip in "${INTERFACE_IPV4S[@]}"; do
            if [ "$ip" = "$BIND_IP" ]; then
                LOCAL_IP="$BIND_IP"
                print_success "Selected local IPv4 (from --bind-ip): $LOCAL_IP"
                return 0
            fi
        done
        print_error "Bind IP '$BIND_IP' is not assigned to interface $INTERFACE"
        print_info "Available IPv4 addresses: ${INTERFACE_IPV4S[*]}"
        return 1
    fi

    # Single-IP interface: select automatically.
    if [ ${#INTERFACE_IPV4S[@]} -eq 1 ]; then
        LOCAL_IP="${INTERFACE_IPV4S[0]}"
        print_success "Local IPv4: $LOCAL_IP"
        return 0
    fi

    # Multi-IP interface: ask user which IP should be used.
    print_warning "Multiple IPv4 addresses detected on interface $INTERFACE"
    print_info "Choose the IP address to use for this tunnel:"
    local i=1
    for ip in "${INTERFACE_IPV4S[@]}"; do
        echo -e "  ${WHITE}$i)${NC} $ip"
        ((i++))
    done

    local choice=""
    while true; do
        read -p "Select IPv4 (1-${#INTERFACE_IPV4S[@]}, default: 1): " choice
        choice=$(echo "$choice" | tr -d '[:space:]')
        if [ -z "$choice" ]; then
            choice="1"
        fi

        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#INTERFACE_IPV4S[@]} ]; then
            LOCAL_IP="${INTERFACE_IPV4S[$((choice-1))]}"
            print_success "Selected local IPv4: $LOCAL_IP"
            return 0
        fi

        print_warning "Invalid choice. Enter a number between 1 and ${#INTERFACE_IPV4S[@]}."
    done
}

# Select interface + IPv4 from all global IPv4 addresses on the server.
# This is used when INTERFACE is not specified and multiple IPs exist.
select_interface_and_ipv4() {
    local entries=()
    local line=""

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        entries+=("$line")
    done < <(ip -o -4 addr show scope global | awk '{print $2" "$4}' | cut -d'/' -f1)

    if [ ${#entries[@]} -eq 0 ]; then
        return 1
    fi

    if [ ${#entries[@]} -eq 1 ]; then
        INTERFACE=$(echo "${entries[0]}" | awk '{print $1}')
        LOCAL_IP=$(echo "${entries[0]}" | awk '{print $2}')
        return 0
    fi

    print_warning "Multiple IPv4 addresses detected on this server"
    print_info "Choose interface/IP to use for this tunnel:"

    local i=1
    local iface=""
    local ip=""
    for line in "${entries[@]}"; do
        iface=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        echo -e "  ${WHITE}$i)${NC} $iface -> $ip"
        ((i++))
    done

    local choice=""
    while true; do
        read -p "Select interface/IP (1-${#entries[@]}, default: 1): " choice
        choice=$(echo "$choice" | tr -d '[:space:]')
        if [ -z "$choice" ]; then
            choice="1"
        fi

        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#entries[@]} ]; then
            line="${entries[$((choice-1))]}"
            INTERFACE=$(echo "$line" | awk '{print $1}')
            LOCAL_IP=$(echo "$line" | awk '{print $2}')
            return 0
        fi

        print_warning "Invalid choice. Enter a number between 1 and ${#entries[@]}."
    done
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run with sudo"
        exit 1
    fi
    print_success "Running with root privileges"
}

# Install script to /usr/local/bin for easy access
install_to_bin() {
    print_header "Installing Paqet Script"
    
    local script_path="/usr/local/bin/paqet"
    local source_script="$0"
    
    # Get the real path of the script
    if [ -L "$source_script" ]; then
        source_script=$(readlink -f "$source_script")
    fi
    
    # Copy script to /usr/local/bin
    print_info "Installing to $script_path..."
    cp "$source_script" "$script_path"
    chmod +x "$script_path"
    
    if [ -f "$script_path" ]; then
        print_success "Paqet script installed successfully!"
        echo ""
        print_info "You can now use the following commands:"
        echo "  sudo paqet              - Open main menu"
        echo "  sudo paqet --status     - List all tunnels"
        echo "  sudo paqet --manage     - Open management menu"
        echo "  sudo paqet --update-core - Update paqet binary core"
        echo "  sudo paqet --help       - Show all options"
        echo ""
    else
        print_error "Failed to install script"
        exit 1
    fi
}

# Uninstall script from /usr/local/bin
uninstall_from_bin() {
    print_header "Uninstalling Paqet Script"
    
    local script_path="/usr/local/bin/paqet"
    
    if [ -f "$script_path" ]; then
        rm -f "$script_path"
        print_success "Paqet script removed from $script_path"
    else
        print_warning "Paqet script not found in $script_path"
    fi
}

# Install dependencies
install_dependencies() {
    print_header "Installing Dependencies"
    
    # Detect OS
    if [ -f /etc/debian_version ]; then
        DISTRO="debian"
        print_info "Detected Debian/Ubuntu system"
        print_info "Installing libpcap-dev..."
        apt-get update -qq
        apt-get install -y libpcap-dev net-tools iptables arp-scan curl wget git >/dev/null 2>&1
    elif [ -f /etc/redhat-release ]; then
        DISTRO="redhat"
        print_info "Detected RHEL/CentOS/Fedora system"
        print_info "Installing libpcap-devel..."
        yum install -y libpcap-devel net-tools iptables arp-tools curl wget git >/dev/null 2>&1
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
        print_info "Detected Arch Linux system"
        print_info "Installing libpcap..."
        pacman -S --noconfirm libpcap net-tools iptables curl wget git >/dev/null 2>&1
    else
        print_warning "Could not detect Linux distribution"
        print_info "Please manually install: libpcap-dev (or libpcap-devel)"
        DISTRO="unknown"
    fi
    
    print_success "Dependencies installed"
}

# Get network interface details
get_network_details() {
    print_header "Network Detection"

    local selected_from_global=false

    if [ -z "$INTERFACE" ]; then
        if [ -n "$BIND_IP" ]; then
            # Auto-detect interface from provided bind IP.
            INTERFACE=$(ip -o -4 addr show scope global | awk -v ip="$BIND_IP" '{
                split($4, a, "/");
                if (a[1] == ip) {
                    print $2;
                    exit
                }
            }')
            if [ -z "$INTERFACE" ]; then
                print_error "Could not find an interface for bind IP '$BIND_IP'"
                exit 1
            fi
        else
            # If server has multiple global IPv4s, ask for exact interface/IP pair.
            if select_interface_and_ipv4; then
                selected_from_global=true
            else
                # Fallback to default interface auto-detection.
                INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
                if [ -z "$INTERFACE" ]; then
                    print_error "Could not auto-detect network interface"
                    exit 1
                fi
            fi
        fi
    fi

    print_info "Using network interface: $INTERFACE"

    # Collect local IPv4 addresses for this interface.
    INTERFACE_IPV4S=()
    while IFS= read -r ip; do
        [ -n "$ip" ] || continue
        INTERFACE_IPV4S+=("$ip")
    done < <(ip -o -4 addr show dev "$INTERFACE" scope global | awk '{print $4}' | cut -d'/' -f1)

    # Fallback if no scope=global address exists in this environment.
    if [ ${#INTERFACE_IPV4S[@]} -eq 0 ]; then
        while IFS= read -r ip; do
            [ -n "$ip" ] || continue
            INTERFACE_IPV4S+=("$ip")
        done < <(ip -o -4 addr show dev "$INTERFACE" | awk '{print $4}' | cut -d'/' -f1)
    fi

    if [ ${#INTERFACE_IPV4S[@]} -eq 0 ]; then
        print_error "Could not get IP for interface $INTERFACE"
        exit 1
    fi

    if [ "$selected_from_global" = true ]; then
        if [[ "$LOCAL_IP" =~ [[:space:]] ]] || [ -z "$LOCAL_IP" ]; then
            print_error "Invalid selected IPv4 address: '$LOCAL_IP'"
            exit 1
        fi
        print_success "Selected local IPv4: $LOCAL_IP"
    else
        # Ensure only one IP is used in generated configs (important for multi-IP servers).
        if ! select_local_ipv4; then
            exit 1
        fi
    fi

    # Get gateway IP
    GATEWAY_IP=$(ip route | grep default | awk '{print $3}')
    if [ -z "$GATEWAY_IP" ]; then
        print_error "Could not determine gateway IP"
        exit 1
    fi
    print_success "Gateway IP: $GATEWAY_IP"
    
    # Get gateway MAC
    GATEWAY_MAC=$(arp -n "$GATEWAY_IP" 2>/dev/null | grep "$GATEWAY_IP" | awk '{print $3}')
    if [ -z "$GATEWAY_MAC" ] || [ "$GATEWAY_MAC" = "<incomplete>" ]; then
        print_warning "Could not get gateway MAC via arp, attempting with ping/arp..."
        ping -c 1 "$GATEWAY_IP" >/dev/null 2>&1
        GATEWAY_MAC=$(arp -n "$GATEWAY_IP" 2>/dev/null | grep "$GATEWAY_IP" | awk '{print $3}')
        if [ -z "$GATEWAY_MAC" ]; then
            print_error "Could not determine gateway MAC address"
            print_info "Run: arp -a"
            exit 1
        fi
    fi
    print_success "Gateway MAC: $GATEWAY_MAC"
}

# Generate encryption key
generate_encryption_key() {
    print_header "Generating Encryption Key"
    
    if [ -z "$ENCRYPTION_KEY" ]; then
        # Try to use paqet's secret command if available
        local paqet_binary
        paqet_binary=$(resolve_paqet_binary)
        if [ -n "$paqet_binary" ]; then
            ENCRYPTION_KEY=$("$paqet_binary" secret 2>/dev/null)
            if [ -n "$ENCRYPTION_KEY" ]; then
                print_success "Generated key using paqet secret command"
                return
            fi
        fi
        
        # Fallback to openssl
        if command -v openssl &> /dev/null; then
            ENCRYPTION_KEY=$(openssl rand -base64 32)
            print_success "Generated encryption key (using openssl)"
        else
            ENCRYPTION_KEY=$(dd if=/dev/urandom bs=1 count=32 2>/dev/null | base64)
            print_success "Generated encryption key (using /dev/urandom)"
        fi
    else
        print_success "Using provided encryption key"
    fi
    
    print_info "Encryption Key: $ENCRYPTION_KEY"
}

# Download paqet binary
download_paqet_binary() {
    local force_update="${1:-false}"
    print_header "Paqet Binary Download"

    local existing_binary=""
    existing_binary=$(resolve_paqet_binary 2>/dev/null || true)

    if [ "$force_update" != "true" ]; then
        if [ -f "$PAQET_PATH/paqet" ] && ! is_script_paqet "$PAQET_PATH/paqet"; then
            print_success "Paqet binary already exists: $PAQET_PATH/paqet"
            return 0
        fi

        if [ -n "$existing_binary" ]; then
            print_success "Paqet binary found in PATH: $existing_binary"
            return 0
        fi

        print_info "Paqet binary not found, downloading..."
    else
        if [ -n "$existing_binary" ]; then
            print_info "Updating existing Paqet binary: $existing_binary"
        else
            print_info "No existing Paqet binary found, installing latest version"
        fi
    fi

    # Detect architecture
    local arch=$(uname -m)
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local paqet_arch=""

    case "$arch" in
        x86_64|amd64)
            paqet_arch="amd64"
            ;;
        aarch64|arm64)
            paqet_arch="arm64"
            ;;
        armv7l|armhf)
            paqet_arch="arm32"
            ;;
        mips)
            paqet_arch="mips"
            ;;
        mipsel|mipsle)
            paqet_arch="mipsle"
            ;;
        mips64)
            paqet_arch="mips64"
            ;;
        mips64el|mips64le)
            paqet_arch="mips64le"
            ;;
        *)
            print_error "Unsupported architecture: $arch"
            print_info "Please download manually from: https://github.com/diyakou/paqet/releases"
            return 1
            ;;
    esac

    print_info "Detected: $os-$paqet_arch"

    # Get latest version from GitHub API
    print_info "Checking latest version..."
    local version
    version=$(get_latest_paqet_version)

    if [ -z "$version" ]; then
        if [ "$force_update" = "true" ]; then
            print_error "Could not fetch latest release version from GitHub API"
            print_info "Please check internet access and try again"
            return 1
        fi
        version="v1.0.0-optimized"
        print_warning "Could not fetch latest version, using fallback: $version"
    else
        print_info "Latest version: $version"
    fi

    local repo="diyakou/paqet"
    local filename="paqet-linux-${paqet_arch}-${version}.tar.gz"
    local download_url="https://github.com/${repo}/releases/download/$version/$filename"

    print_info "Release repo: $repo"
    print_info "Downloading: $filename"

    local temp_dir
    temp_dir=$(mktemp -d)
    local archive_path="$temp_dir/$filename"
    local extract_dir="$temp_dir/extracted"

    # Download with gh (authenticated for private repos) or curl/wget
    if command -v gh &> /dev/null && gh auth status -t -h github.com >/dev/null 2>&1; then
        print_info "Using GitHub CLI authentication"
        gh release download "$version" --repo "$repo" --pattern "$filename" -D "$temp_dir" >/dev/null 2>&1
        if [ -f "$temp_dir/$filename" ]; then
            mv "$temp_dir/$filename" "$archive_path"
        fi
    else
        if command -v curl &> /dev/null; then
            curl -fL -o "$archive_path" "$download_url"
        elif command -v wget &> /dev/null; then
            wget -O "$archive_path" "$download_url"
        else
            print_error "Neither gh nor curl/wget found. Please install one of them."
            rm -rf "$temp_dir"
            return 1
        fi
    fi

    if [ ! -f "$archive_path" ]; then
        print_error "Download failed. If the repo is private, run: gh auth login"
        print_info "Manual download: https://github.com/${repo}/releases"
        rm -rf "$temp_dir"
        return 1
    fi

    print_success "Download completed"

    # Extract binary to temporary directory
    print_info "Extracting binary..."
    mkdir -p "$extract_dir"
    tar -xzf "$archive_path" -C "$extract_dir" 2>/dev/null

    if [ $? -ne 0 ]; then
        print_error "Extraction failed"
        rm -rf "$temp_dir"
        return 1
    fi

    # Find the paqet binary (could be in root or subdirectory)
    local binary_path=""
    if [ -f "$extract_dir/paqet" ]; then
        binary_path="$extract_dir/paqet"
    else
        # Search for any executable that looks like paqet
        binary_path=$(find "$extract_dir" -type f -name "*paqet*" ! -name "*.tar.gz" 2>/dev/null | head -1)
    fi
    
    if [ -z "$binary_path" ] || [ ! -f "$binary_path" ]; then
        print_error "Could not find paqet binary in extracted archive"
        print_info "Archive contents:"
        tar -tzf "$archive_path" | head -20
        rm -rf "$temp_dir"
        return 1
    fi

    # Install to existing binary path when updating, otherwise use PAQET_PATH/paqet
    local install_target="$PAQET_PATH/paqet"
    if [ "$force_update" = "true" ] && [ -n "$existing_binary" ]; then
        install_target="$existing_binary"
    fi

    mkdir -p "$(dirname "$install_target")"
    cp "$binary_path" "$install_target"

    if [ $? -ne 0 ]; then
        print_error "Failed to copy binary to: $install_target"
        rm -rf "$temp_dir"
        return 1
    fi

    # Make executable
    chmod +x "$install_target"

    # Cleanup
    rm -rf "$temp_dir"

    if [ -f "$install_target" ]; then
        print_success "Paqet binary installed: $install_target"
        print_info "Version: $version"
        return 0
    else
        print_error "Installation failed"
        return 1
    fi
}

# Restart currently active paqet services after core updates
restart_active_tunnels_after_update() {
    local active_found=0

    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            local service_name
            service_name=$(basename "$service_file" .service)
            if systemctl is-active --quiet "$service_name"; then
                active_found=1
                print_info "Restarting $service_name..."
                if systemctl restart "$service_name"; then
                    print_success "$service_name restarted"
                else
                    print_warning "Failed to restart $service_name"
                fi
            fi
        fi
    done

    if [ "$active_found" -eq 0 ]; then
        print_info "No active paqet tunnels found to restart"
    fi
}

# Force update paqet core binary to the latest release
update_paqet_core() {
    print_header "Updating Paqet Core"
    check_root

    if download_paqet_binary "true"; then
        restart_active_tunnels_after_update
        print_success "Paqet core update completed"
    else
        print_error "Paqet core update failed"
        return 1
    fi
}

# Create client configuration
create_client_config() {
    local config_file="$1"
    
    print_header "Creating Client Configuration (Iran - Direct Tunnel)"
    
    cat > "$config_file" << EOF
# Paqet Client Configuration - Iran (Direct Tunnel)
# This client connects to the Kharej server
role: "client"

# Logging configuration
log:
  level: "info"  # none, debug, info, warn, error, fatal
EOF

    if [ "$PROXY_TYPE" = "socks5" ]; then
        cat >> "$config_file" << EOF

# SOCKS5 proxy configuration (client mode)
socks5:
  - listen: "127.0.0.1:1080"    # SOCKS5 proxy listen address
    username: ""                 # Optional SOCKS5 authentication
    password: ""                 # Optional SOCKS5 authentication
EOF
    else
        cat >> "$config_file" << EOF

# Port forwarding configuration
# Forward local ports to targets through tunnel
# You can add multiple forwarding rules
forward:
EOF
        # Support multiple forwards (FORWARD_RULES is semicolon-separated)
        if [ -n "$FORWARD_RULES" ]; then
            IFS=';' read -ra RULES <<< "$FORWARD_RULES"
            for rule in "${RULES[@]}"; do
                # Parse: local_port:target_host:target_port[:protocol]
                IFS=':' read -ra PARTS <<< "$rule"
                local local_port="${PARTS[0]}"
                local target_host="${PARTS[1]}"
                local target_port="${PARTS[2]}"
                local protocol="${PARTS[3]:-tcp}"
                
                cat >> "$config_file" << EOF
  - listen: ":$local_port"
    target: "$target_host:$target_port"
    protocol: "$protocol"
EOF
            done
        else
            # Fallback to single forward for backward compatibility
            cat >> "$config_file" << EOF
  - listen: ":$FORWARD_LOCAL_PORT"
    target: "$FORWARD_TARGET_HOST:$FORWARD_TARGET_PORT"
    protocol: "tcp"
EOF
        fi
    fi

    cat >> "$config_file" << EOF

# Network interface settings
network:
  interface: "$INTERFACE"
  
  # IPv4 configuration
  ipv4:
    addr: "$LOCAL_IP:0"          # Local IP with random port assignment
    router_mac: "$GATEWAY_MAC"   # Gateway/router MAC address
  
  # TCP flags for packet crafting
  tcp:
    local_flag: ["PA"]           # Local TCP flags (Push+Ack)
    remote_flag: ["PA"]          # Remote TCP flags (Push+Ack)
  
  # PCAP settings
  pcap:
        sockbuf: $CLIENT_PCAP_SOCKBUF             # PCAP buffer for client

# Server connection settings (Kharej server)
server:
  addr: "$SERVER_ADDRESS:$SERVER_PORT"  # Kharej paqet server address and port

# Transport protocol configuration
transport:
  protocol: "kcp"                # Transport protocol
  conn: $CONN_COUNT              # Number of connections (Parallel Connections)
  
  # KCP protocol settings
  kcp:
    mode: "$KCP_MODE"               # KCP mode: normal, fast, fast2, fast3, manual
    # Manual settings will only be used if mode is "manual"
    mtu: $MTU                    # Maximum transmission unit
    nodelay: $KCP_NODELAY         # Whether to enable nodelay mode
    interval: $KCP_INTERVAL       # Protocol internal work interval (ms)
    resend: $KCP_RESEND           # Fast resend parameter
    nocongestion: $KCP_NC         # Whether to disable congestion control

    rcvwnd: $KCP_RCVWND           # Receive window size (increase for high throughput)
    sndwnd: $KCP_SNDWND           # Receive window size (increase for high throughput)
    
    # Encryption settings
    block: "aes"                 # Encryption algorithm
    key: "$ENCRYPTION_KEY"       # MUST match server key
    
    # Buffer settings
    smuxbuf: $KCP_SMUXBUF         # SMUX buffer
    streambuf: $KCP_STREAMBUF     # Stream buffer
EOF

    chmod 600 "$config_file"
    print_success "Client configuration created: $config_file"
    if [ "$PROXY_TYPE" = "socks5" ]; then
        print_info "SOCKS5 proxy will listen on 127.0.0.1:1080"
    else
        print_info "Port forwarding configured:"
        if [ -n "$FORWARD_RULES" ]; then
            IFS=';' read -ra RULES <<< "$FORWARD_RULES"
            for rule in "${RULES[@]}"; do
                IFS=':' read -ra PARTS <<< "$rule"
                print_info "  :${PARTS[0]} -> ${PARTS[1]}:${PARTS[2]}"
            done
        fi
    fi
}

create_server_config() {
    local config_file="$1"
    
    print_header "Creating Server Configuration (Kharej - Direct Tunnel)"
    
    cat > "$config_file" << EOF
# Paqet Server Configuration - Kharej (Direct Tunnel)
# This server accepts connections from Iran client
role: "server"

# Logging configuration
log:
  level: "info"  # none, debug, info, warn, error, fatal

# Server listen configuration
listen:
  addr: ":$SERVER_PORT"          # Server listen port

# Network interface settings
network:
  interface: "$INTERFACE"
  
  # IPv4 configuration
  ipv4:
    addr: "$LOCAL_IP:$SERVER_PORT"      # Server IPv4 and port (must match listen.addr)
    router_mac: "$GATEWAY_MAC"          # Gateway/router MAC address
  
  # TCP flags for packet crafting
  tcp:
    local_flag: ["PA"]                  # Local TCP flags (Push+Ack)
    remote_flag: ["PA"]                 # Remote TCP flags (Push+Ack)
  
  # PCAP settings
  pcap:
        sockbuf: $SERVER_PCAP_SOCKBUF                    # PCAP buffer for server

# Transport protocol configuration
transport:
  protocol: "kcp"                # Transport protocol
  conn: $CONN_COUNT              # Number of connections (Parallel Connections)
  
  # KCP protocol settings
  kcp:
    mode: "$KCP_MODE"               # KCP mode: normal, fast, fast2, fast3, manual
    # Manual settings will only be used if mode is "manual"
    mtu: $MTU                    # Maximum transmission unit
    nodelay: $KCP_NODELAY         # Whether to enable nodelay mode
    interval: $KCP_INTERVAL       # Protocol internal work interval (ms)
    resend: $KCP_RESEND           # Fast resend parameter
    nocongestion: $KCP_NC         # Whether to disable congestion control

    rcvwnd: $KCP_RCVWND           # Receive window size (increase for high throughput)
    sndwnd: $KCP_SNDWND           # Receive window size (increase for high throughput)
    
    # Encryption settings
    block: "aes"                 # Encryption algorithm
    key: "$ENCRYPTION_KEY"       # MUST match client key
    
    # Buffer settings
    smuxbuf: $KCP_SMUXBUF         # SMUX buffer
    streambuf: $KCP_STREAMBUF     # Stream buffer
EOF

    chmod 600 "$config_file"
    print_success "Server configuration created: $config_file"
}

# Setup iptables firewall rules
setup_firewall_rules() {
    local port="$1"
    
    print_header "Setting Up Firewall Rules"
    
    print_warning "Configuring iptables to bypass kernel interference on port $port"
    if [ "$port" = "80" ] || [ "$port" = "443" ]; then
        print_warning "Using port $port is risky for paqet; avoid standard ports to prevent side effects on normal server traffic."
    fi
    
    # Rule 1: Bypass connection tracking
    print_info "Rule 1: Bypassing connection tracking (NOTRACK)..."
    iptables -t raw -A PREROUTING -p tcp --dport "$port" -j NOTRACK
    iptables -t raw -A OUTPUT -p tcp --sport "$port" -j NOTRACK
    
    # Rule 2: Drop RST packets
    print_info "Rule 2: Dropping RST packets..."
    iptables -t mangle -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP
    
    # Verify rules
    print_info "Verifying iptables rules..."
    iptables -t raw -L PREROUTING -n | grep "$port" >/dev/null && print_success "PREROUTING rule applied"
    iptables -t mangle -L OUTPUT -n | grep "$port" >/dev/null && print_success "OUTPUT rule applied"
    
    # Save rules for persistence
    if [ "$DISTRO" = "debian" ]; then
        print_info "Saving iptables rules for persistence..."
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        print_success "Rules saved to /etc/iptables/rules.v4"
        
        # Install iptables-persistent if not present
        if ! dpkg -l | grep iptables-persistent >/dev/null 2>&1; then
            print_info "Installing iptables-persistent..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent >/dev/null 2>&1
            print_success "iptables-persistent installed"
        fi
    elif [ "$DISTRO" = "redhat" ]; then
        print_info "Saving iptables rules for persistence..."
        service iptables save
        systemctl enable iptables
        print_success "Rules saved and iptables enabled"
    fi
}

# Optimize kernel/OS settings for tunneling
detect_primary_interface() {
    local iface=""
    if command -v ip >/dev/null 2>&1; then
        iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}')
        if [ -z "$iface" ]; then
            iface=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5; exit}')
        fi
    fi
    echo "$iface"
}

apply_nic_optimizations() {
    local iface="$1"
    if [ -z "$iface" ]; then
        print_warning "No interface detected for NIC queue tuning"
        return
    fi
    if ! ip link show "$iface" >/dev/null 2>&1; then
        print_warning "Interface $iface not found; skipping NIC tuning"
        return
    fi

    print_info "Applying NIC queue optimizations on $iface..."
    if ip link set dev "$iface" txqueuelen 10000 2>/dev/null; then
        print_success "Set $iface txqueuelen to 10000"
    else
        print_warning "Could not set txqueuelen on $iface"
    fi

    if command -v ethtool >/dev/null 2>&1; then
        if ethtool -G "$iface" rx 4096 tx 4096 >/dev/null 2>&1; then
            print_success "Set NIC ring buffers (rx/tx=4096)"
        else
            print_info "NIC ring buffer tuning not supported on $iface"
        fi

        if ethtool -K "$iface" rx on tx on sg on tso on gso on gro on >/dev/null 2>&1; then
            print_success "Enabled NIC offloads (rx/tx/sg/tso/gso/gro)"
        else
            print_info "NIC offload tuning not supported on $iface"
        fi

        ethtool -C "$iface" adaptive-rx on adaptive-tx on >/dev/null 2>&1 || true
    else
        print_warning "ethtool not installed; skipped ring/offload tuning"
    fi
}

optimize_kernel() {
    print_header "Kernel & OS Optimization"
    
    local sysctl_file="/etc/sysctl.d/99-paqet-tunnel.conf"
    local backup_file="/etc/sysctl.d/99-paqet-tunnel.conf.backup"
    local tune_iface="${INTERFACE:-}"
    if [ -z "$tune_iface" ]; then
        tune_iface=$(detect_primary_interface)
    fi
    
    # Backup existing config if present
    if [ -f "$sysctl_file" ]; then
        cp "$sysctl_file" "$backup_file"
        print_info "Backed up existing config to $backup_file"
    fi
    
    print_info "Applying network optimizations..."
    
    cat > "$sysctl_file" << 'EOF'
# Paqet Tunnel Kernel Optimizations
# Generated by paqet deployment script

# ============================================
# TCP/UDP Buffer Sizes
# ============================================
# Aggressive buffer sizes for high-throughput tunnels
net.core.rmem_default = 16777216
net.core.rmem_max = 268435456
net.core.wmem_default = 16777216
net.core.wmem_max = 268435456
net.core.optmem_max = 67108864
net.ipv4.udp_rmem_min = 262144
net.ipv4.udp_wmem_min = 262144
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# ============================================
# Connection Handling
# ============================================
# Increase connection tracking table size
net.netfilter.nf_conntrack_max = 2097152
net.nf_conntrack_max = 2097152

# Reduce connection tracking timeouts
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 120

# Increase local port range
net.ipv4.ip_local_port_range = 1024 65535

# ============================================
# TCP Performance Tuning
# ============================================
# Enable TCP Fast Open
net.ipv4.tcp_fastopen = 3

# Disable TCP slow start after idle
net.ipv4.tcp_slow_start_after_idle = 0

# Enable TCP BBR congestion control (if available)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Increase TCP max orphans
net.ipv4.tcp_max_orphans = 1048576

# Increase max SYN backlog
net.ipv4.tcp_max_syn_backlog = 65535
net.core.somaxconn = 65535

# Reduce TIME_WAIT overhead
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1

# Enable TCP timestamps
net.ipv4.tcp_timestamps = 1

# Enable TCP selective acknowledgments
net.ipv4.tcp_sack = 1

# Probe lower MTU paths if needed
net.ipv4.tcp_mtu_probing = 1

# Reduce TCP keepalive time
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 10

# ============================================
# Memory & Queue Settings
# ============================================
# Increase network device backlog
net.core.netdev_max_backlog = 250000
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000

# Allow larger in-flight packets per socket
net.ipv4.tcp_notsent_lowat = 16384

# ============================================
# IP Forwarding (for tunneling)
# ============================================
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Relax reverse path filtering for asymmetric tunnel routing
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

# ============================================
# File Descriptor Limits
# ============================================
fs.file-max = 4194304
fs.nr_open = 4194304
EOF

    # Apply sysctl settings
    print_info "Loading kernel parameters..."
    
    # Try to apply settings, ignore errors for unavailable parameters
    sysctl -p "$sysctl_file" 2>/dev/null || true
    
    # Check if BBR is available, fallback to cubic if not
    if ! sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        print_warning "BBR congestion control not available, using cubic"
        sed -i 's/tcp_congestion_control = bbr/tcp_congestion_control = cubic/' "$sysctl_file"
        sysctl -w net.ipv4.tcp_congestion_control=cubic 2>/dev/null || true
    fi

    # Apply NIC queue/offload tuning for the active interface
    apply_nic_optimizations "$tune_iface"
    
    # Update limits.conf for file descriptors
    local limits_file="/etc/security/limits.d/99-paqet.conf"
    cat > "$limits_file" << 'EOF'
# Paqet Tunnel - Increase file descriptor limits
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
    
    print_success "Kernel optimizations applied"
    print_info "Settings saved to $sysctl_file"
    if [ -n "$tune_iface" ]; then
        print_info "Optimized network interface: $tune_iface"
    fi
    print_info "Note: Some settings require reconnect/restart (reboot gives full effect)"
}

optimize_kernel_settings() {
    optimize_kernel
}

# Remove kernel optimizations
remove_kernel_optimizations() {
    print_header "Removing Kernel Optimizations"
    
    local sysctl_file="/etc/sysctl.d/99-paqet-tunnel.conf"
    local limits_file="/etc/security/limits.d/99-paqet.conf"
    
    if [ -f "$sysctl_file" ]; then
        rm -f "$sysctl_file"
        print_success "Removed $sysctl_file"
    fi
    
    if [ -f "$limits_file" ]; then
        rm -f "$limits_file"
        print_success "Removed $limits_file"
    fi
    
    # Reload default sysctl
    sysctl --system >/dev/null 2>&1
    print_info "System defaults restored (reboot recommended)"
}

# Create systemd service file (supports custom tunnel name for multiple tunnels)
create_systemd_service() {
    local mode="$1"
    local config_file="$2"
    local paqet_path="$3"
    local tunnel_name="${4:-}"  # Optional tunnel name for multi-tunnel support
    
    local service_name
    if [ -n "$tunnel_name" ]; then
        service_name="paqet-${mode}-${tunnel_name}"
    else
        service_name="paqet-$mode"
    fi
    local service_file="/etc/systemd/system/${service_name}.service"
    
    print_header "Creating Systemd Service"
    
    # Find paqet binary
    local paqet_binary
    paqet_binary=$(resolve_paqet_binary)
    if [ -z "$paqet_binary" ]; then
        print_warning "Could not find paqet binary, skipping systemd service creation"
        return
    fi
    if command -v readlink &> /dev/null; then
        paqet_binary=$(readlink -f "$paqet_binary" 2>/dev/null || echo "$paqet_binary")
    fi
    
    cat > "$service_file" << EOF
[Unit]
Description=Paqet Tunnel ($mode)
After=network.target
Documentation=https://github.com/diyakou/paqet

[Service]
Type=simple
User=root
WorkingDirectory=$paqet_path
ExecStart=$paqet_binary run -c $config_file
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$service_name

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "$service_file"
    systemctl daemon-reload
    print_success "Systemd service created: $service_file"
    print_info "To enable and start: sudo systemctl enable $service_name && sudo systemctl start $service_name"
    print_info "To view logs: sudo journalctl -u $service_name -f"
}

# Create startup script (supports custom tunnel name)
create_startup_script() {
    local mode="$1"
    local config_file="$2"
    local paqet_path="$3"
    local tunnel_name="${4:-}"  # Optional tunnel name
    
    local script_name
    if [ -n "$tunnel_name" ]; then
        script_name="start-${mode}-${tunnel_name}.sh"
    else
        script_name="start-${mode}.sh"
    fi
    local script_path="$paqet_path/$script_name"
    
    print_header "Creating Startup Script"
    
    # Find paqet binary
    local paqet_binary
    paqet_binary=$(resolve_paqet_binary)
    if [ -z "$paqet_binary" ]; then
        print_warning "Could not find paqet binary"
        return
    fi
    
    cat > "$script_path" << EOF
#!/bin/bash
# Paqet Startup Script

if [[ \$EUID -ne 0 ]]; then
    echo "ERROR: This script must be run with sudo"
    exit 1
fi

MODE="\$1"
CONFIG="\$2"

if [ -z "\$MODE" ] || [ -z "\$CONFIG" ]; then
    echo "Usage: \$0 <client|server> <config_file>"
    exit 1
fi

PAQET_PATH="\$(dirname "\$0")"
PAQET_BIN="$paqet_binary"

if [ ! -x "\$PAQET_BIN" ] && [ -x "\$PAQET_PATH/paqet" ]; then
    PAQET_BIN="\$PAQET_PATH/paqet"
fi

if [ ! -x "\$PAQET_BIN" ]; then
    echo "ERROR: paqet binary not found"
    exit 1
fi

echo "Starting Paqet (\$MODE)..."
echo "Configuration: \$CONFIG"
echo "Binary: \$PAQET_BIN"
echo ""

"\$PAQET_BIN" run -c "\$CONFIG"
EOF

    chmod +x "$script_path"
    print_success "Startup script created: $script_path"
    print_info "Usage: sudo $script_path client|server config.yaml"
}

# Test connectivity
test_connectivity() {
    local config_file="$1"
    
    print_header "Testing Connectivity"
    
    local paqet_bin
    paqet_bin=$(resolve_paqet_binary)
    if [ -z "$paqet_bin" ]; then
        print_warning "paqet binary not found, skipping connectivity test"
        return
    fi
    
    print_info "Testing connection (this sends a ping packet)..."
    "$paqet_bin" ping -c "$config_file" 2>/dev/null || true
    print_info "Check server logs for ping response"
}

# Test configuration file
test_config_file() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        print_error "Configuration file not found: $config_file"
        return 1
    fi
    
    print_success "Configuration file exists: $config_file"
    
    # Basic YAML validation
    if grep -q "role:" "$config_file" && (grep -q "\"client\"" "$config_file" || grep -q "\"server\"" "$config_file"); then
        print_success "Configuration file validated"
        return 0
    else
        print_error "Invalid configuration: role not properly set"
        return 1
    fi
}

# ============================================
# MULTI-TUNNEL MANAGEMENT FUNCTIONS
# ============================================

# Resolve config path from a systemd service file.
# Supports relative "-c config.yaml" by prefixing WorkingDirectory.
resolve_service_config_path() {
    local service_file="$1"
    local config=""
    local working_dir=""

    config=$(awk '
        /^ExecStart=/ {
            for (i = 1; i <= NF; i++) {
                if ($i == "-c" && (i + 1) <= NF) {
                    print $(i + 1)
                    exit
                }
            }
        }
    ' "$service_file")

    # Strip optional surrounding quotes.
    config="${config%\"}"
    config="${config#\"}"

    if [ -z "$config" ]; then
        echo ""
        return
    fi

    if [[ "$config" = /* ]]; then
        echo "$config"
        return
    fi

    working_dir=$(awk -F= '/^WorkingDirectory=/{print $2; exit}' "$service_file")
    if [ -n "$working_dir" ]; then
        echo "${working_dir%/}/$config"
    else
        echo "$config"
    fi
}

# Extract tunnel port from config:
# - server role: listen.addr port
# - client role: server.addr port
extract_tunnel_port_from_config() {
    local config_file="$1"
    [ -f "$config_file" ] || { echo ""; return; }

    local port=""
    if grep -q 'role:[[:space:]]*"server"' "$config_file"; then
        port=$(awk '
            /^listen:[[:space:]]*$/ { in_block=1; next }
            in_block && /^[^[:space:]]/ { in_block=0 }
            in_block && /addr:[[:space:]]*"/ {
                if (match($0, /:([0-9]+)"/, m)) {
                    print m[1]
                    exit
                }
            }
        ' "$config_file")
    else
        port=$(awk '
            /^server:[[:space:]]*$/ { in_block=1; next }
            in_block && /^[^[:space:]]/ { in_block=0 }
            in_block && /addr:[[:space:]]*"/ {
                if (match($0, /:([0-9]+)"/, m)) {
                    print m[1]
                    exit
                }
            }
        ' "$config_file")
    fi

    echo "$port"
}

# List all paqet tunnels (services)
list_tunnels() {
    print_header "Paqet Tunnel Status"
    
    local found=0
    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            found=1
            local service_name=$(basename "$service_file" .service)
            local status=$(systemctl is-active "$service_name" 2>/dev/null || echo "unknown")
            local enabled=$(systemctl is-enabled "$service_name" 2>/dev/null || echo "unknown")
            
            # Get config file from service
            local config
            config=$(resolve_service_config_path "$service_file")
            local tunnel_port=""
            if [ -n "$config" ] && [ -f "$config" ]; then
                tunnel_port=$(extract_tunnel_port_from_config "$config")
            fi
            
            case "$status" in
                active)
                    echo -e "${GREEN}● ${service_name}${NC}"
                    ;;
                inactive)
                    echo -e "${RED}○ ${service_name}${NC}"
                    ;;
                *)
                    echo -e "${YELLOW}? ${service_name}${NC}"
                    ;;
            esac
            echo -e "    Status:  $status"
            echo -e "    Enabled: $enabled"
            echo -e "    Config:  $config"
            if [ -n "$tunnel_port" ]; then
                echo -e "    Port:    $tunnel_port"
            fi
            echo ""
        fi
    done
    
    if [ $found -eq 0 ]; then
        print_warning "No paqet tunnels found"
    fi
}

# Monitor all tunnels
monitor_tunnels() {
    print_header "Monitoring All Paqet Tunnels"
    print_info "Press Ctrl+C to stop monitoring"
    echo ""
    
    # Get all paqet services
    local services=""
    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            local service_name=$(basename "$service_file" .service)
            services="$services -u $service_name"
        fi
    done
    
    if [ -z "$services" ]; then
        print_warning "No paqet tunnels found to monitor"
        return
    fi
    
    # Follow logs from all services
    journalctl -f $services
}

# Start all tunnels
start_all_tunnels() {
    print_header "Starting All Paqet Tunnels"
    
    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            local service_name=$(basename "$service_file" .service)
            print_info "Starting $service_name..."
            systemctl start "$service_name"
            if [ $? -eq 0 ]; then
                print_success "$service_name started"
            else
                print_error "Failed to start $service_name"
            fi
        fi
    done
}

# Stop all tunnels
stop_all_tunnels() {
    print_header "Stopping All Paqet Tunnels"
    
    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            local service_name=$(basename "$service_file" .service)
            print_info "Stopping $service_name..."
            systemctl stop "$service_name"
            if [ $? -eq 0 ]; then
                print_success "$service_name stopped"
            else
                print_error "Failed to stop $service_name"
            fi
        fi
    done
}

# Restart all tunnels
restart_all_tunnels() {
    print_header "Restarting All Paqet Tunnels"
    
    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            local service_name=$(basename "$service_file" .service)
            print_info "Restarting $service_name..."
            systemctl restart "$service_name"
            if [ $? -eq 0 ]; then
                print_success "$service_name restarted"
            else
                print_error "Failed to restart $service_name"
            fi
        fi
    done
}

# Remove a specific tunnel
remove_tunnel() {
    local tunnel_name="$1"
    
    if [ -z "$tunnel_name" ]; then
        print_header "Remove Tunnel"
        echo "Available tunnels:"
        echo ""
        
        local i=1
        local tunnels=()
        for service_file in /etc/systemd/system/paqet-*.service; do
            if [ -f "$service_file" ]; then
                local service_name=$(basename "$service_file" .service)
                tunnels+=("$service_name")
                echo "  $i) $service_name"
                ((i++))
            fi
        done
        
        if [ ${#tunnels[@]} -eq 0 ]; then
            print_warning "No tunnels found"
            return
        fi
        
        echo ""
        read -p "Enter tunnel number to remove (or 'cancel'): " choice
        
        if [ "$choice" = "cancel" ]; then
            return
        fi
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#tunnels[@]} ]; then
            tunnel_name="${tunnels[$((choice-1))]}"
        else
            print_error "Invalid selection"
            return
        fi
    fi
    
    print_warning "Removing tunnel: $tunnel_name"
    
    # Stop and disable service
    systemctl stop "$tunnel_name" 2>/dev/null
    systemctl disable "$tunnel_name" 2>/dev/null
    
    # Remove service file
    rm -f "/etc/systemd/system/${tunnel_name}.service"
    
    # Find and remove config file
    local config_pattern="${tunnel_name#paqet-}"
    rm -f "config-${config_pattern}.yaml" 2>/dev/null
    rm -f "start-${config_pattern}.sh" 2>/dev/null
    
    systemctl daemon-reload
    
    print_success "Tunnel $tunnel_name removed"
}

# Deploy a single tunnel (for multi-tunnel mode)
deploy_single_tunnel() {
    local tunnel_name="$1"
    local config_file="config-${MODE}-${tunnel_name}.yaml"
    
    print_header "Deploying Tunnel: $tunnel_name"
    
    # Create configuration
    if [ "$MODE" = "server" ]; then
        create_server_config "$config_file"
        setup_firewall_rules "$SERVER_PORT"
    else
        validate_forward_rules || return 1
        create_client_config "$config_file"
    fi
    
    # Validate configuration
    test_config_file "$config_file"
    
    # Create systemd service with tunnel name
    create_systemd_service "$MODE" "$config_file" "$(pwd)" "$tunnel_name"
    
    # Create startup script with tunnel name
    create_startup_script "$MODE" "$config_file" "$(pwd)" "$tunnel_name"
    
    print_success "Tunnel '$tunnel_name' deployed successfully"
    print_info "Config: $config_file"
    print_info "Service: paqet-${MODE}-${tunnel_name}"
}

# Main deployment function
deploy_paqet() {
    local config_file="$1"
    local tunnel_name="${2:-}"  # Optional tunnel name for multi-tunnel
    
    print_header "Paqet Direct Tunnel Deployment"
    print_info "Mode: $MODE"
    if [ -n "$tunnel_name" ]; then
        print_info "Tunnel: $tunnel_name"
    fi
    
    # Check prerequisites
    check_root
    install_dependencies
    
    # Download paqet binary if needed
    download_paqet_binary || exit 1
    
    # Get network details
    get_network_details
    
    # Generate encryption key (only if not already set)
    if [ -z "$ENCRYPTION_KEY" ]; then
        generate_encryption_key
    fi
    
    # Create configuration
    if [ "$MODE" = "server" ]; then
        create_server_config "$config_file"
        setup_firewall_rules "$SERVER_PORT"
    else
        validate_forward_rules || exit 1
        create_client_config "$config_file"
    fi
    
    # Validate configuration
    test_config_file "$config_file"
    
    # Create systemd service (with tunnel name if provided)
    create_systemd_service "$MODE" "$config_file" "$(pwd)" "$tunnel_name"
    
    # Create startup script (with tunnel name if provided)
    create_startup_script "$MODE" "$config_file" "$(pwd)" "$tunnel_name"
    
    # Test connectivity for client
    if [ "$MODE" = "client" ] && [ -n "$SERVER_ADDRESS" ]; then
        test_connectivity "$config_file"
    fi
    
    # Determine service name for summary
    local service_name
    if [ -n "$tunnel_name" ]; then
        service_name="paqet-${MODE}-${tunnel_name}"
    else
        service_name="paqet-$MODE"
    fi
    
    # Auto-start the tunnel
    print_header "Starting Tunnel"
    print_info "Enabling and starting $service_name..."
    systemctl enable "$service_name" 2>/dev/null
    systemctl start "$service_name"
    
    if [ $? -eq 0 ]; then
        sleep 2  # Give it time to start
        if systemctl is-active --quiet "$service_name"; then
            print_success "$service_name started successfully!"
        else
            print_warning "$service_name may have failed to start. Check logs:"
            print_info "   sudo journalctl -u $service_name -n 20"
        fi
    else
        print_error "Failed to start $service_name"
        print_info "Check logs: sudo journalctl -u $service_name -n 20"
    fi
    
    # Print summary
    print_header "Deployment Summary"
    print_success "Mode: $MODE"
    if [ -n "$tunnel_name" ]; then
        print_success "Tunnel Name: $tunnel_name"
    fi
    print_success "Configuration: $config_file"
    print_success "Service: $service_name"
    print_info "Encryption Key: $ENCRYPTION_KEY"
    echo ""
    
    # Show service status
    local status=$(systemctl is-active "$service_name" 2>/dev/null || echo "unknown")
    if [ "$status" = "active" ]; then
        echo -e "  Status: ${GREEN}● Running${NC}"
    else
        echo -e "  Status: ${RED}○ Not running${NC}"
    fi
    
    echo ""
    print_info "USEFUL COMMANDS:"
    print_info "  View logs:    sudo journalctl -u $service_name -f"
    print_info "  Restart:      sudo systemctl restart $service_name"
    print_info "  Stop:         sudo systemctl stop $service_name"
    
    if [ "$MODE" = "client" ]; then
        if [ "$PROXY_TYPE" = "socks5" ]; then
            print_info ""
            print_info "SOCKS5 proxy available at 127.0.0.1:1080"
            print_info "  Test: curl -v https://httpbin.org/ip --proxy socks5h://127.0.0.1:1080"
        else
            print_info ""
            print_info "Port forwards active:"
            # Show all forwarded ports
            if [ -n "$FORWARD_RULES" ]; then
                IFS=';' read -ra RULES <<< "$FORWARD_RULES"
                for rule in "${RULES[@]}"; do
                    IFS=':' read -ra PARTS <<< "$rule"
                    print_info "   Local :${PARTS[0]} -> ${PARTS[1]}:${PARTS[2]}"
                done
            fi
        fi
    fi
}

# Parse command line arguments
MODE=""
CONFIG_FILE=""
INTERFACE=""
SERVER_ADDRESS=""
SERVER_PORT="9999"
BIND_IP=""
PROXY_TYPE="socks5"
FORWARD_LOCAL_PORT="8080"
FORWARD_TARGET_HOST=""
FORWARD_TARGET_PORT="80"
FORWARD_RULES=""  # Semicolon-separated: "local:target_host:target_port[:protocol];..."
FORWARD_PORTS=""  # User input format: "443=443,8443=8080"
ENCRYPTION_KEY=""
PAQET_PATH="."
PAQET_REPO="diyakou/paqet"
KCP_MODE="fast2"
CONN_COUNT="3"
MTU="1280"
KCP_NODELAY=1
KCP_INTERVAL=20
KCP_RESEND=2
KCP_NC=1
KCP_RCVWND=2048
KCP_SNDWND=2048
KCP_SMUXBUF=4194304
KCP_STREAMBUF=2097152
CLIENT_PCAP_SOCKBUF="4194304"
SERVER_PCAP_SOCKBUF="8388608"

# Check for CLI management commands FIRST (before parsing deployment options)
# These commands are handled by handle_cli_args() at the end of the script
if [[ $# -gt 0 ]]; then
    case "$1" in
        --status|--list|--start-all|--stop-all|--restart-all|--monitor|--remove|--manage|--options|--reports|--logs|--errors|--optimize|--update-core|--update|--install|--uninstall|--help|-h)
            # Skip the deployment options parsing - let the CLI handler at the end process these
            :
            ;;
        *)
            # Parse deployment options only for non-management commands
            while [[ $# -gt 0 ]]; do
                case $1 in
                    --config-file)
                        CONFIG_FILE="$2"
                        shift 2
                        ;;
                    --interface)
                        INTERFACE="$2"
                        shift 2
                        ;;
                    --server-address)
                        SERVER_ADDRESS="$2"
                        shift 2
                        ;;
                    --server-port)
                        SERVER_PORT=$(normalize_port "$2")
                        if [ -z "$SERVER_PORT" ]; then
                            print_error "Invalid server port: $2"
                            exit 1
                        fi
                        shift 2
                        ;;
                    --bind-ip)
                        BIND_IP=$(echo "$2" | xargs)
                        if [[ "$BIND_IP" =~ [[:space:]] ]]; then
                            print_error "Invalid bind IP: '$2' (provide a single IPv4 address)"
                            exit 1
                        fi
                        shift 2
                        ;;
                    --key)
                        ENCRYPTION_KEY="$2"
                        shift 2
                        ;;
                    --proxy-type)
                        PROXY_TYPE="$2"
                        shift 2
                        ;;
                    --kcp-mode)
                        KCP_MODE="$2"
                        shift 2
                        ;;
                    --conn-count)
                        CONN_COUNT="$2"
                        shift 2
                        ;;
                    --forward-local-port)
                        FORWARD_LOCAL_PORT="$2"
                        shift 2
                        ;;
                    --forward-target-host)
                        FORWARD_TARGET_HOST="$2"
                        shift 2
                        ;;
                    --forward-target-port)
                        FORWARD_TARGET_PORT="$2"
                        shift 2
                        ;;
                    --forward-rules)
                        FORWARD_RULES="$2"
                        shift 2
                        ;;
                    --paqet-path)
                        PAQET_PATH="$2"
                        shift 2
                        ;;
                    --mtu)
                        MTU="$2"
                        shift 2
                        ;;
                    *)
                        print_error "Unknown deployment option: $1"
                        echo ""
                        echo "Use --help to see available options"
                        exit 1
                        ;;
                esac
            done
            ;;
    esac
fi

# Legacy: Old deployment option parsing (kept for backward compatibility but now unused)
# The parsing is now done in the case block above
if false; then
while [[ $# -gt 0 ]]; do
    case $1 in
        --config-file)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --interface)
            INTERFACE="$2"
            shift 2
            ;;
        --server-address)
            SERVER_ADDRESS="$2"
            shift 2
            ;;
        --server-port)
            SERVER_PORT=$(normalize_port "$2")
            if [ -z "$SERVER_PORT" ]; then
                print_error "Invalid server port: $2"
                exit 1
            fi
            shift 2
            ;;
        --bind-ip)
            BIND_IP=$(echo "$2" | xargs)
            if [[ "$BIND_IP" =~ [[:space:]] ]]; then
                print_error "Invalid bind IP: '$2' (provide a single IPv4 address)"
                exit 1
            fi
            shift 2
            ;;
        --key)
            ENCRYPTION_KEY="$2"
            shift 2
            ;;
        --proxy-type)
            PROXY_TYPE="$2"
            shift 2
            ;;
        --kcp-mode)
            KCP_MODE="$2"
            shift 2
            ;;
        --conn-count)
            CONN_COUNT="$2"
            shift 2
            ;;
        --forward-local-port)
            FORWARD_LOCAL_PORT="$2"
            shift 2
            ;;
        --forward-target-host)
            FORWARD_TARGET_HOST="$2"
            shift 2
            ;;
        --forward-target-port)
            FORWARD_TARGET_PORT="$2"
            shift 2
            ;;
        --forward-rules)
            FORWARD_RULES="$2"
            shift 2
            ;;
        --paqet-path)
            PAQET_PATH="$2"
            shift 2
            ;;
        --mtu)
            MTU="$2"
            shift 2
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done
fi  # End of legacy block

# Interactive input collection for single tunnel
get_single_tunnel_input() {
    echo -e "\n${GREEN}Mode: ${MODE^^}${NC}"
    
    # Client-specific questions
    if [ "$MODE" = "client" ]; then
        echo -e "\n${CYAN}[CLIENT - Iran/Internal Setup]${NC}"
        
        # Get server address
        while [ -z "$SERVER_ADDRESS" ]; do
            read -p "Enter Kharej SERVER IP address: " response
            SERVER_ADDRESS=$(echo "$response" | tr -d '[:space:]')
        done
        
        # Get server port
        read -p "Enter SERVER port (press Enter for default: 9999): " response
        if [ -n "$response" ]; then
            local normalized
            normalized=$(normalize_port "$response")
            if [ -n "$normalized" ]; then
                SERVER_PORT="$normalized"
            else
                print_warning "Invalid port input, using default: 9999"
                SERVER_PORT="9999"
            fi
        fi
        
        # Get proxy type
        echo -e "\n${YELLOW}Proxy Configuration:${NC}"
        proxyResponse=""
        while [ "$proxyResponse" != "1" ] && [ "$proxyResponse" != "2" ]; do
            echo -e "  ${WHITE}1) SOCKS5 Proxy (127.0.0.1:1080)${NC}"
            echo -e "  ${WHITE}2) Port Forwarding (forward specific port)${NC}"
            read -p "Choose proxy type (1 or 2): " proxyResponse
        done
        
        if [ "$proxyResponse" = "2" ]; then
            PROXY_TYPE="forward"
            FORWARD_TARGET_HOST="$SERVER_ADDRESS"
            
            echo -e "\n${YELLOW}Port Forwarding Configuration:${NC}"
            echo -e "  Format: local_port=target_port (e.g., 443=443, 8443=8080)"
            echo -e "  You can enter multiple ports separated by comma"
            echo -e "  All ports will forward to the Kharej server IP"
            echo -e "  ${YELLOW}Do not map target_port to the paqet server port (${SERVER_PORT}) on the same host.${NC}\n"
            
            while [ -z "$FORWARD_PORTS" ]; do
                read -p "Enter port mappings (e.g., 443=443, 8443=8080): " FORWARD_PORTS
                FORWARD_PORTS=$(echo "$FORWARD_PORTS" | tr -d '[:space:]')
            done
            
            # Parse the port mappings and build FORWARD_RULES
            # Format: local:target_host:target_port;local:target_host:target_port;...
            FORWARD_RULES=""
            IFS=',' read -ra PORT_PAIRS <<< "$FORWARD_PORTS"
            for pair in "${PORT_PAIRS[@]}"; do
                # Parse local=target format
                local_port=$(echo "$pair" | cut -d'=' -f1)
                target_port=$(echo "$pair" | cut -d'=' -f2)
                if [ -n "$local_port" ] && [ -n "$target_port" ]; then
                    if [ -n "$FORWARD_RULES" ]; then
                        FORWARD_RULES="${FORWARD_RULES};"
                    fi
                    # Target host is Kharej server IP (traffic forwarded through tunnel to server)
                    FORWARD_RULES="${FORWARD_RULES}${local_port}:${SERVER_ADDRESS}:${target_port}"
                    echo -e "  ${GREEN}✓ Forward: :${local_port} -> ${SERVER_ADDRESS}:${target_port}${NC}"
                fi
            done
            
            echo -e "\n  ${GREEN}Total ports configured: ${#PORT_PAIRS[@]}${NC}"
        else
            PROXY_TYPE="socks5"
            echo -e "  ${GREEN}SOCKS5 proxy will be available at 127.0.0.1:1080${NC}"
        fi
        
        # Get KCP Configuration
        echo -e "\n${YELLOW}KCP Configuration (Connection Tuning):${NC}"
        echo -e "  Default connections: 3 (Balanced, lower bandwidth overhead)"
        read -p "Enter number of parallel connections (default: 3): " response
        if [ -n "$response" ]; then
            CONN_COUNT=$(echo "$response" | tr -d '[:space:]')
        fi

        echo -e "\n  Performance Modes:"
        echo -e "  ${WHITE}1) fast${NC}"
        echo -e "  ${WHITE}2) fast2 (More aggressive)${NC}"
        echo -e "  ${WHITE}3) fast3 (Most aggressive - very high bandwidth usage)${NC}"
        echo -e "  ${WHITE}4) manual (Custom low-level parameters)${NC}"
        read -p "Choose KCP mode (1-4, default: 2): " kcpResponse
        
        case "$kcpResponse" in
            1) KCP_MODE="fast" ;;
            2) KCP_MODE="fast2" ;;
            3) KCP_MODE="fast3" ;;
            4) KCP_MODE="manual" ;;
            *) KCP_MODE="fast2" ;;
        esac
        echo -e "  ${GREEN}Selected Mode: $KCP_MODE${NC}"

        if [ "$KCP_MODE" = "manual" ]; then
            echo -e "\n${YELLOW}Manual Presets:${NC}"
            echo -e "  ${WHITE}1) Normal (Balanced)${NC}"
            echo -e "  ${WHITE}2) Gaming (Low latency)${NC}"
            echo -e "  ${WHITE}3) Streaming/Downloading (High throughput)${NC}"
            read -p "Choose manual preset (1-3, default: 1): " presetResponse
            case "$presetResponse" in
                2) apply_kcp_preset "gaming" "client" ;;
                3) apply_kcp_preset "streaming" "client" ;;
                *) apply_kcp_preset "normal" "client" ;;
            esac
            echo -e "  ${GREEN}Manual preset applied.${NC}"
        else
            apply_kcp_mode_defaults "client" "$KCP_MODE"
        fi

        # Get MTU
        echo -e "\n${YELLOW}MTU Configuration:${NC}"
        echo -e "  Default: 1280 (Recommended for most networks)"
        echo -e "  Lower values (1200-1300) may help with unstable connections"
        read -p "Enter MTU value (default: 1280): " response
        if [ -n "$response" ]; then
            MTU=$(echo "$response" | tr -d '[:space:]')
        fi
        echo -e "  ${GREEN}MTU: $MTU${NC}"

        # Get encryption key
        echo -e "\n${YELLOW}Encryption Key:${NC}"
        echo -e "  You need the encryption key from the Kharej server."
        read -p "Enter encryption key (or press Enter to generate new): " response
        if [ -n "$response" ]; then
            ENCRYPTION_KEY="$response"
        fi
    else
        echo -e "\n${CYAN}[SERVER - Kharej/External Setup]${NC}"
        
        # Get server port
        read -p "Enter port to listen on (press Enter for default: 9999): " response
        if [ -n "$response" ]; then
            local normalized
            normalized=$(normalize_port "$response")
            if [ -n "$normalized" ]; then
                SERVER_PORT="$normalized"
            else
                print_warning "Invalid port input, using default: 9999"
                SERVER_PORT="9999"
            fi
        fi
        
        # Get KCP Configuration for server
        echo -e "\n${YELLOW}KCP Configuration (Connection Tuning):${NC}"
        echo -e "  Default connections: 3 (Balanced, lower bandwidth overhead)"
        read -p "Enter number of parallel connections (default: 3): " response
        if [ -n "$response" ]; then
            CONN_COUNT=$(echo "$response" | tr -d '[:space:]')
        fi
        echo -e "  ${GREEN}Connection count: $CONN_COUNT${NC}"
        
        echo -e "\n  Performance Modes:"
        echo -e "  ${WHITE}1) fast${NC}"
        echo -e "  ${WHITE}2) fast2 (More aggressive)${NC}"
        echo -e "  ${WHITE}3) fast3 (Most aggressive - very high bandwidth usage)${NC}"
        echo -e "  ${WHITE}4) manual (Custom low-level parameters)${NC}"
        read -p "Choose KCP mode (1-4, default: 2): " kcpResponse
        
        case "$kcpResponse" in
            1) KCP_MODE="fast" ;;
            2) KCP_MODE="fast2" ;;
            3) KCP_MODE="fast3" ;;
            4) KCP_MODE="manual" ;;
            *) KCP_MODE="fast2" ;;
        esac
        echo -e "  ${GREEN}Selected Mode: $KCP_MODE${NC}"

        if [ "$KCP_MODE" = "manual" ]; then
            echo -e "\n${YELLOW}Manual Presets:${NC}"
            echo -e "  ${WHITE}1) Normal (Balanced)${NC}"
            echo -e "  ${WHITE}2) Gaming (Low latency)${NC}"
            echo -e "  ${WHITE}3) Streaming/Downloading (High throughput)${NC}"
            read -p "Choose manual preset (1-3, default: 1): " presetResponse
            case "$presetResponse" in
                2) apply_kcp_preset "gaming" "server" ;;
                3) apply_kcp_preset "streaming" "server" ;;
                *) apply_kcp_preset "normal" "server" ;;
            esac
            echo -e "  ${GREEN}Manual preset applied.${NC}"
        else
            apply_kcp_mode_defaults "server" "$KCP_MODE"
        fi
        
        # Get MTU for server
        echo -e "\n${YELLOW}MTU Configuration:${NC}"
        echo -e "  Default: 1280 (Recommended for most networks)"
        echo -e "  Lower values (1200-1300) may help with unstable connections"
        read -p "Enter MTU value (default: 1280): " response
        if [ -n "$response" ]; then
            MTU=$(echo "$response" | tr -d '[:space:]')
        fi
        echo -e "  ${GREEN}MTU: $MTU${NC}"
        
        # Generate encryption key NOW and show it
        echo -e "\n${YELLOW}Encryption Key:${NC}"
        
        # Generate key immediately
        if command -v openssl &> /dev/null; then
            ENCRYPTION_KEY=$(openssl rand -base64 32)
        else
            ENCRYPTION_KEY=$(dd if=/dev/urandom bs=1 count=32 2>/dev/null | base64)
        fi
        
        echo -e "\n${CYAN}============================================${NC}"
        echo -e "${RED}  IMPORTANT: COPY THIS ENCRYPTION KEY!${NC}"
        echo -e "${CYAN}============================================${NC}"
        echo -e "\n${GREEN}$ENCRYPTION_KEY${NC}\n"
        echo -e "${CYAN}============================================${NC}"
        echo -e "${YELLOW}You will need this key when setting up the client.${NC}"
        echo -e "${YELLOW}Press Enter after you have copied the key...${NC}"
        read -p ""
    fi
    
    # Optional: Network interface
    echo -e "\n${YELLOW}Network Interface:${NC}"
    echo -e "  Leave empty for auto-detection"
    read -p "Enter network interface name (or press Enter for auto): " response
    if [ -n "$response" ]; then
        INTERFACE=$(echo "$response" | tr -d '[:space:]')
    fi
}

# Collect input for multiple tunnels (client connecting to multiple servers)
get_multi_client_input() {
    echo -e "\n${CYAN}[MULTI-SERVER CLIENT SETUP]${NC}"
    echo -e "${YELLOW}You will connect this client to multiple Kharej servers.${NC}"
    echo -e "${YELLOW}Each server will have its own tunnel and service.${NC}\n"
    
    # Get global KCP settings (shared across all tunnels)
    echo -e "${YELLOW}Global KCP Configuration (applies to all tunnels):${NC}"
    echo -e "  Default connections: 3 (Balanced, lower bandwidth overhead)"
    read -p "Enter number of parallel connections (default: 3): " response
    if [ -n "$response" ]; then
        CONN_COUNT=$(echo "$response" | tr -d '[:space:]')
    fi
    echo -e "  ${GREEN}Connection count: $CONN_COUNT${NC}"
    
    echo -e "\n  Performance Modes:"
    echo -e "  ${WHITE}1) fast${NC}"
    echo -e "  ${WHITE}2) fast2 (More aggressive)${NC}"
    echo -e "  ${WHITE}3) fast3 (Most aggressive - very high bandwidth usage)${NC}"
    echo -e "  ${WHITE}4) manual (Custom low-level parameters)${NC}"
    read -p "Choose KCP mode (1-4, default: 2): " kcpResponse
    
    case "$kcpResponse" in
        1) KCP_MODE="fast" ;;
        2) KCP_MODE="fast2" ;;
        3) KCP_MODE="fast3" ;;
        4) KCP_MODE="manual" ;;
        *) KCP_MODE="fast2" ;;
    esac
    echo -e "  ${GREEN}Selected Mode: $KCP_MODE${NC}"

    if [ "$KCP_MODE" = "manual" ]; then
        echo -e "\n${YELLOW}Manual Presets:${NC}"
        echo -e "  ${WHITE}1) Normal (Balanced)${NC}"
        echo -e "  ${WHITE}2) Gaming (Low latency)${NC}"
        echo -e "  ${WHITE}3) Streaming/Downloading (High throughput)${NC}"
        read -p "Choose manual preset (1-3, default: 1): " presetResponse
        case "$presetResponse" in
            2) apply_kcp_preset "gaming" "client" ;;
            3) apply_kcp_preset "streaming" "client" ;;
            *) apply_kcp_preset "normal" "client" ;;
        esac
        echo -e "  ${GREEN}Manual preset applied.${NC}"
    else
        apply_kcp_mode_defaults "client" "$KCP_MODE"
    fi
    
    echo -e "\n${YELLOW}MTU Configuration:${NC}"
    echo -e "  Default: 1280 (Recommended for most networks)"
    echo -e "  Lower values (1200-1300) may help with unstable connections"
    read -p "Enter MTU value (default: 1280): " response
    if [ -n "$response" ]; then
        MTU=$(echo "$response" | tr -d '[:space:]')
    fi
    echo -e "  ${GREEN}MTU: $MTU${NC}"
    
    local tunnel_count=0
    local add_more="yes"
    
    while [ "$add_more" = "yes" ] || [ "$add_more" = "y" ]; do
        ((tunnel_count++))
        echo -e "\n${CYAN}--- Tunnel #$tunnel_count ---${NC}"
        
        # Get tunnel name
        local tunnel_name=""
        read -p "Enter a name for this tunnel (e.g., server1, kharej1): " tunnel_name
        tunnel_name=$(echo "$tunnel_name" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        if [ -z "$tunnel_name" ]; then
            tunnel_name="server$tunnel_count"
        fi
        TUNNEL_NAMES+=("$tunnel_name")
        
        # Get server address
        local server_addr=""
        while [ -z "$server_addr" ]; do
            read -p "Enter SERVER IP address for '$tunnel_name': " server_addr
            server_addr=$(echo "$server_addr" | tr -d '[:space:]')
        done
        TUNNEL_SERVERS+=("$server_addr")
        
        # Get server port
        local server_port="9999"
        read -p "Enter SERVER port (default: 9999): " response
        if [ -n "$response" ]; then
            local normalized
            normalized=$(normalize_port "$response")
            if [ -n "$normalized" ]; then
                server_port="$normalized"
            else
                print_warning "Invalid port input, using default: 9999"
                server_port="9999"
            fi
        fi
        TUNNEL_PORTS+=("$server_port")
        
        # Get port forwarding
        echo -e "\n${YELLOW}Port Forwarding for '$tunnel_name':${NC}"
        echo -e "  Format: local_port=target_port (e.g., 443=443, 8443=8080)"
        local forward_ports=""
        while [ -z "$forward_ports" ]; do
            read -p "Enter port mappings: " forward_ports
            forward_ports=$(echo "$forward_ports" | tr -d '[:space:]')
        done
        
        # Convert to FORWARD_RULES format
        local forward_rules=""
        IFS=',' read -ra PORT_PAIRS <<< "$forward_ports"
        for pair in "${PORT_PAIRS[@]}"; do
            local local_port=$(echo "$pair" | cut -d'=' -f1)
            local target_port=$(echo "$pair" | cut -d'=' -f2)
            if [ -n "$local_port" ] && [ -n "$target_port" ]; then
                if [ -n "$forward_rules" ]; then
                    forward_rules="${forward_rules};"
                fi
                forward_rules="${forward_rules}${local_port}:${server_addr}:${target_port}"
                echo -e "  ${GREEN}✓ Forward: :${local_port} -> ${server_addr}:${target_port}${NC}"
            fi
        done
        TUNNEL_FORWARD_RULES+=("$forward_rules")
        
        # Get encryption key
        echo -e "\n${YELLOW}Encryption Key for '$tunnel_name':${NC}"
        local enc_key=""
        read -p "Enter encryption key from server: " enc_key
        if [ -z "$enc_key" ]; then
            # Generate new key if not provided
            if command -v openssl &> /dev/null; then
                enc_key=$(openssl rand -base64 32)
            else
                enc_key=$(dd if=/dev/urandom bs=1 count=32 2>/dev/null | base64)
            fi
            echo -e "  ${YELLOW}Generated new key: $enc_key${NC}"
        fi
        TUNNEL_KEYS+=("$enc_key")
        
        echo -e "\n${GREEN}✓ Tunnel '$tunnel_name' configured${NC}"
        
        # Ask for more
        read -p "Add another server? (yes/no): " add_more
        add_more=$(echo "$add_more" | tr '[:upper:]' '[:lower:]')
    done
    
    echo -e "\n${GREEN}Total tunnels configured: $tunnel_count${NC}"
}

# Collect input for multiple tunnels (server accepting multiple clients)
get_multi_server_input() {
    echo -e "\n${CYAN}[MULTI-CLIENT SERVER SETUP]${NC}"
    echo -e "${YELLOW}This server will accept connections from multiple Iran clients.${NC}"
    echo -e "${YELLOW}Each client will have its own tunnel, port, and encryption key.${NC}\n"
    
    # Get global KCP settings (shared across all tunnels)
    echo -e "${YELLOW}Global KCP Configuration (applies to all tunnels):${NC}"
    echo -e "  Default connections: 3 (Balanced, lower bandwidth overhead)"
    read -p "Enter number of parallel connections (default: 3): " response
    if [ -n "$response" ]; then
        CONN_COUNT=$(echo "$response" | tr -d '[:space:]')
    fi
    echo -e "  ${GREEN}Connection count: $CONN_COUNT${NC}"
    
    echo -e "\n  Performance Modes:"
    echo -e "  ${WHITE}1) fast${NC}"
    echo -e "  ${WHITE}2) fast2 (More aggressive)${NC}"
    echo -e "  ${WHITE}3) fast3 (Most aggressive - very high bandwidth usage)${NC}"
    echo -e "  ${WHITE}4) manual (Custom low-level parameters)${NC}"
    read -p "Choose KCP mode (1-4, default: 2): " kcpResponse
    
    case "$kcpResponse" in
        1) KCP_MODE="fast" ;;
        2) KCP_MODE="fast2" ;;
        3) KCP_MODE="fast3" ;;
        4) KCP_MODE="manual" ;;
        *) KCP_MODE="fast2" ;;
    esac
    echo -e "  ${GREEN}Selected Mode: $KCP_MODE${NC}"

    if [ "$KCP_MODE" = "manual" ]; then
        echo -e "\n${YELLOW}Manual Presets:${NC}"
        echo -e "  ${WHITE}1) Normal (Balanced)${NC}"
        echo -e "  ${WHITE}2) Gaming (Low latency)${NC}"
        echo -e "  ${WHITE}3) Streaming/Downloading (High throughput)${NC}"
        read -p "Choose manual preset (1-3, default: 1): " presetResponse
        case "$presetResponse" in
            2) apply_kcp_preset "gaming" "server" ;;
            3) apply_kcp_preset "streaming" "server" ;;
            *) apply_kcp_preset "normal" "server" ;;
        esac
        echo -e "  ${GREEN}Manual preset applied.${NC}"
    else
        apply_kcp_mode_defaults "server" "$KCP_MODE"
    fi
    
    echo -e "\n${YELLOW}MTU Configuration:${NC}"
    echo -e "  Default: 1280 (Recommended for most networks)"
    echo -e "  Lower values (1200-1300) may help with unstable connections"
    read -p "Enter MTU value (default: 1280): " response
    if [ -n "$response" ]; then
        MTU=$(echo "$response" | tr -d '[:space:]')
    fi
    echo -e "  ${GREEN}MTU: $MTU${NC}"
    
    local tunnel_count=0
    local add_more="yes"
    
    while [ "$add_more" = "yes" ] || [ "$add_more" = "y" ]; do
        ((tunnel_count++))
        echo -e "\n${CYAN}--- Client Tunnel #$tunnel_count ---${NC}"
        
        # Get tunnel name
        local tunnel_name=""
        read -p "Enter a name for this tunnel (e.g., client1, iran1): " tunnel_name
        tunnel_name=$(echo "$tunnel_name" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        if [ -z "$tunnel_name" ]; then
            tunnel_name="client$tunnel_count"
        fi
        TUNNEL_NAMES+=("$tunnel_name")
        
        # Get server port (each client tunnel needs different port)
        local server_port=""
        local default_port=$((9999 + tunnel_count - 1))
        read -p "Enter port to listen on for '$tunnel_name' (default: $default_port): " server_port
        if [ -z "$server_port" ]; then
            server_port="$default_port"
        fi
        local normalized
        normalized=$(normalize_port "$server_port")
        if [ -n "$normalized" ]; then
            server_port="$normalized"
        else
            print_warning "Invalid port input, using default: $default_port"
            server_port="$default_port"
        fi
        TUNNEL_PORTS+=("$server_port")
        
        # Generate encryption key
        local enc_key=""
        if command -v openssl &> /dev/null; then
            enc_key=$(openssl rand -base64 32)
        else
            enc_key=$(dd if=/dev/urandom bs=1 count=32 2>/dev/null | base64)
        fi
        TUNNEL_KEYS+=("$enc_key")
        
        echo -e "\n${CYAN}============================================${NC}"
        echo -e "${RED}  ENCRYPTION KEY FOR '$tunnel_name'${NC}"
        echo -e "${CYAN}============================================${NC}"
        echo -e "\n${GREEN}$enc_key${NC}\n"
        echo -e "${CYAN}============================================${NC}"
        echo -e "${YELLOW}Give this key to the '$tunnel_name' client!${NC}"
        echo -e "${YELLOW}Port: $server_port${NC}"
        echo -e "${YELLOW}Press Enter after copying...${NC}"
        read -p ""
        
        echo -e "${GREEN}✓ Tunnel '$tunnel_name' configured on port $server_port${NC}"
        
        # Ask for more
        read -p "Add another client tunnel? (yes/no): " add_more
        add_more=$(echo "$add_more" | tr '[:upper:]' '[:lower:]')
    done
    
    echo -e "\n${GREEN}Total client tunnels configured: $tunnel_count${NC}"
}

# Deploy multiple tunnels
deploy_multi_tunnels() {
    print_header "Deploying Multiple Tunnels"
    
    # Check prerequisites first
    check_root
    install_dependencies
    download_paqet_binary || exit 1
    get_network_details
    
    for i in "${!TUNNEL_NAMES[@]}"; do
        local tunnel_name="${TUNNEL_NAMES[$i]}"
        local config_file="config-${MODE}-${tunnel_name}.yaml"
        
        echo -e "\n${CYAN}--- Deploying: $tunnel_name ---${NC}"
        
        if [ "$MODE" = "client" ]; then
            SERVER_ADDRESS="${TUNNEL_SERVERS[$i]}"
            SERVER_PORT="${TUNNEL_PORTS[$i]}"
            FORWARD_RULES="${TUNNEL_FORWARD_RULES[$i]}"
            ENCRYPTION_KEY="${TUNNEL_KEYS[$i]}"
            PROXY_TYPE="forward"

            validate_forward_rules || return 1
            create_client_config "$config_file"
        else
            SERVER_PORT="${TUNNEL_PORTS[$i]}"
            ENCRYPTION_KEY="${TUNNEL_KEYS[$i]}"
            
            create_server_config "$config_file"
            setup_firewall_rules "$SERVER_PORT"
        fi
        
        # Validate
        test_config_file "$config_file"
        
        # Create service
        create_systemd_service "$MODE" "$config_file" "$(pwd)" "$tunnel_name"
        
        # Create startup script
        create_startup_script "$MODE" "$config_file" "$(pwd)" "$tunnel_name"
        
        # Auto-start the tunnel
        local service_name="paqet-${MODE}-${tunnel_name}"
        print_info "Starting $service_name..."
        systemctl enable "$service_name" 2>/dev/null
        systemctl start "$service_name"
        
        if systemctl is-active --quiet "$service_name"; then
            print_success "Tunnel '$tunnel_name' started successfully"
        else
            print_warning "Tunnel '$tunnel_name' deployed but may not be running"
        fi
    done
    
    # Give tunnels time to fully start
    sleep 2
    
    # Print final summary
    print_header "Multi-Tunnel Deployment Summary"
    echo -e "Total tunnels deployed: ${#TUNNEL_NAMES[@]}\n"
    
    for i in "${!TUNNEL_NAMES[@]}"; do
        local tunnel_name="${TUNNEL_NAMES[$i]}"
        local service_name="paqet-${MODE}-${tunnel_name}"
        local status=$(systemctl is-active "$service_name" 2>/dev/null || echo "unknown")
        
        if [ "$status" = "active" ]; then
            echo -e "${GREEN}●${NC} $tunnel_name"
        else
            echo -e "${RED}○${NC} $tunnel_name"
        fi
        echo -e "    Service: $service_name"
        echo -e "    Config:  config-${MODE}-${tunnel_name}.yaml"
        if [ "$MODE" = "client" ]; then
            echo -e "    Server:  ${TUNNEL_SERVERS[$i]}:${TUNNEL_PORTS[$i]}"
        else
            echo -e "    Port:    ${TUNNEL_PORTS[$i]}"
        fi
        echo ""
    done
    
    print_info "To monitor all tunnels: sudo ./deploy.sh --monitor"
    print_info "To list tunnel status: sudo ./deploy.sh --status"
    print_info "To manage tunnels: sudo ./deploy.sh --manage"
}

# Main menu
show_main_menu() {
    echo ""
    render_kypaqet_banner
    echo -e "${CYAN}"
    ui_line "═" 60
    echo -e "${WHITE}${ICON_DEPLOY}  KYPAQET Installer${NC}"
    echo -e "${CYAN}"
    ui_line "═" 60
    echo -e "${NC}"
    echo -e "${YELLOW}${ICON_TUNNEL}  In a direct tunnel:${NC}"
    echo -e "${YELLOW}   • CLIENT = Iran (internal, connects out)${NC}"
    echo -e "${YELLOW}   • SERVER = Kharej (external, accepts connections)${NC}"
    echo ""
    echo -e "${MAGENTA}${DIM}┌──────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}1)${NC} ${ICON_DEPLOY} Single Tunnel (1 client <-> 1 server)            ${MAGENTA}${DIM}│${NC}"
    echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}2)${NC} 🌐 Multi-Server Client (1 client -> many servers)      ${MAGENTA}${DIM}│${NC}"
    echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}3)${NC} 🏢 Multi-Client Server (1 server <- many clients)      ${MAGENTA}${DIM}│${NC}"
    echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}4)${NC} ${ICON_GEAR} Manage Existing Tunnels                         ${MAGENTA}${DIM}│${NC}"
    echo -e "${MAGENTA}${DIM}└──────────────────────────────────────────────────────────┘${NC}"
    echo ""
    
    local choice=""
    while [ "$choice" != "1" ] && [ "$choice" != "2" ] && [ "$choice" != "3" ] && [ "$choice" != "4" ]; do
        read -p "👉 Enter choice (1-4): " choice
    done
    
    case "$choice" in
        1)
            # Single tunnel mode
            echo -e "\n${CYAN}${ICON_DEPLOY} [SINGLE TUNNEL DEPLOYMENT]${NC}"
            while [ -z "$MODE" ]; do
                read -p "👉 Are you deploying a CLIENT or SERVER? (client/server): " response
                response=$(echo "$response" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
                if [ "$response" = "client" ] || [ "$response" = "server" ]; then
                    MODE="$response"
                else
                    echo -e "${RED}  Please enter 'client' or 'server'${NC}"
                fi
            done
            get_single_tunnel_input
            
            # Confirm
            echo -e "\n${CYAN}============================================${NC}"
            echo -e "${CYAN}  Deployment Summary${NC}"
            echo -e "${CYAN}============================================${NC}"
            echo -e "Mode:       ${MODE^^}"
            if [ "$MODE" = "client" ]; then
                echo -e "Server:     $SERVER_ADDRESS:$SERVER_PORT"
            else
                echo -e "Listen:     0.0.0.0:$SERVER_PORT"
            fi
            echo ""
            
            read -p "✅ Proceed with deployment? (yes/no): " confirm
            confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')
            if [ "$confirm" != "yes" ] && [ "$confirm" != "y" ]; then
                echo -e "${YELLOW}Deployment cancelled.${NC}"
                exit 0
            fi
            
            CONFIG_FILE="config-${MODE}.yaml"
            deploy_paqet "$CONFIG_FILE"
            ;;
        2)
            # Multi-server client
            MODE="client"
            get_multi_client_input
            
            # Confirm
            echo -e "\n${CYAN}============================================${NC}"
            echo -e "Ready to deploy ${#TUNNEL_NAMES[@]} client tunnels"
            echo -e "${CYAN}============================================${NC}"
            read -p "✅ Proceed with deployment? (yes/no): " confirm
            confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')
            if [ "$confirm" != "yes" ] && [ "$confirm" != "y" ]; then
                echo -e "${YELLOW}Deployment cancelled.${NC}"
                exit 0
            fi
            
            deploy_multi_tunnels
            ;;
        3)
            # Multi-client server
            MODE="server"
            get_multi_server_input
            
            # Confirm
            echo -e "\n${CYAN}============================================${NC}"
            echo -e "Ready to deploy ${#TUNNEL_NAMES[@]} server tunnels"
            echo -e "${CYAN}============================================${NC}"
            read -p "✅ Proceed with deployment? (yes/no): " confirm
            confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')
            if [ "$confirm" != "yes" ] && [ "$confirm" != "y" ]; then
                echo -e "${YELLOW}Deployment cancelled.${NC}"
                exit 0
            fi
            
            deploy_multi_tunnels
            ;;
        4)
            # Manage tunnels
            show_management_menu
            ;;
    esac
}

# Management menu
show_management_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}"
        ui_line "═" 60
        echo -e "${WHITE}${ICON_GEAR}  Paqet Tunnel Management${NC}"
        echo -e "${CYAN}"
        ui_line "═" 60
        echo -e "${NC}"
        echo -e "${MAGENTA}${DIM}┌──────────────────────────────────────────────────────────┐${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}1)${NC} 📊 List/Status of all tunnels                         ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}2)${NC} ▶️  Start all tunnels                                 ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}3)${NC} ⏹️  Stop all tunnels                                  ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}4)${NC} 🔄 Restart all tunnels                                ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}5)${NC} ${ICON_LOGS} Monitor all tunnels (live logs)                ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}6)${NC} 🗑️  Remove a tunnel                                   ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}7)${NC} ⚙️  Options (Edit tunnel settings)                    ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}8)${NC} 📈 Reports (View errors/logs)                         ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}9)${NC} ${ICON_SHIELD} Kernel Optimization                           ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}10)${NC} ⬆️  Update Paqet Core                               ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}b)${NC} ${ICON_BACK} Back to main menu                             ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}│${NC} ${WHITE}0)${NC} ${ICON_EXIT} Exit                                         ${MAGENTA}${DIM}│${NC}"
        echo -e "${MAGENTA}${DIM}└──────────────────────────────────────────────────────────┘${NC}"
        echo ""
        
        local choice=""
        read -p "👉 Enter choice: " choice
        
        case "$choice" in
            1) list_tunnels; read -p "Press Enter to continue..." ;;
            2) start_all_tunnels; read -p "Press Enter to continue..." ;;
            3) stop_all_tunnels; read -p "Press Enter to continue..." ;;
            4) restart_all_tunnels; read -p "Press Enter to continue..." ;;
            5) monitor_tunnels ;;
            6) remove_tunnel; read -p "Press Enter to continue..." ;;
            7) show_options_menu ;;
            8) show_reports_menu ;;
            9) show_optimization_menu ;;
            10) update_paqet_core; read -p "Press Enter to continue..." ;;
            b|B) show_main_menu; return ;;
            0) exit 0 ;;
            *) ;;
        esac
    done
}

# ============================================
# KERNEL OPTIMIZATION MENU
# ============================================

show_optimization_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}"
        ui_line "═" 60
        echo -e "${WHITE}${ICON_SHIELD}  Kernel & OS Optimization${NC}"
        echo -e "${CYAN}"
        ui_line "═" 60
        echo -e "${NC}"
        echo ""
        echo -e "  These optimizations improve tunnel performance by:"
        echo -e "  - Increasing network buffer sizes"
        echo -e "  - Enabling TCP BBR congestion control"
        echo -e "  - Optimizing connection tracking"
        echo -e "  - Increasing NIC queue/ring capacity"
        echo -e "  - Increasing file descriptor limits"
        echo ""
        
        # Check if optimizations are already applied
        if [ -f "/etc/sysctl.d/99-paqet-tunnel.conf" ]; then
            echo -e "  Status: ${GREEN}Optimizations Applied${NC}"
        else
            echo -e "  Status: ${YELLOW}Not Applied${NC}"
        fi
        echo ""
        echo -e "  ${WHITE}1)${NC} Apply kernel optimizations"
        echo -e "  ${WHITE}2)${NC} Remove optimizations (restore defaults)"
        echo -e "  ${WHITE}3)${NC} View current settings"
        echo -e "  ${WHITE}4)${NC} Back"
        echo ""
        
        local choice=""
        read -p "Enter choice (1-4): " choice
        
        case "$choice" in
            1) 
                optimize_kernel
                read -p "Press Enter to continue..."
                ;;
            2) 
                remove_kernel_optimizations
                read -p "Press Enter to continue..."
                ;;
            3) 
                view_optimization_status
                read -p "Press Enter to continue..."
                ;;
            4) return ;;
            *) ;;
        esac
    done
}

# View current optimization status
view_optimization_status() {
    print_header "Current Kernel Settings"
    
    echo -e "${CYAN}TCP Congestion Control:${NC}"
    sysctl net.ipv4.tcp_congestion_control 2>/dev/null || echo "  Unable to read"
    
    echo -e "\n${CYAN}Buffer Sizes:${NC}"
    sysctl net.core.rmem_max 2>/dev/null || echo "  Unable to read"
    sysctl net.core.wmem_max 2>/dev/null || echo "  Unable to read"
    sysctl net.ipv4.udp_mem 2>/dev/null || echo "  Unable to read"
    sysctl net.ipv4.tcp_rmem 2>/dev/null || echo "  Unable to read"
    sysctl net.ipv4.tcp_wmem 2>/dev/null || echo "  Unable to read"
    
    echo -e "\n${CYAN}Connection Tracking:${NC}"
    sysctl net.netfilter.nf_conntrack_max 2>/dev/null || echo "  Unable to read"
    
    echo -e "\n${CYAN}Network Queue:${NC}"
    sysctl net.core.netdev_max_backlog 2>/dev/null || echo "  Unable to read"
    local status_iface
    status_iface=$(detect_primary_interface)
    if [ -n "$status_iface" ] && ip link show "$status_iface" >/dev/null 2>&1; then
        local txqlen
        txqlen=$(ip -o link show "$status_iface" | awk '{for (i=1; i<=NF; i++) if ($i=="qlen") {print $(i+1); exit}}')
        if [ -n "$txqlen" ]; then
            echo "  $status_iface txqueuelen=$txqlen"
        fi
    fi

    echo -e "\n${CYAN}IP Forwarding:${NC}"
    sysctl net.ipv4.ip_forward 2>/dev/null || echo "  Unable to read"
    
    echo -e "\n${CYAN}File Descriptors:${NC}"
    echo "  Current limit: $(ulimit -n)"
    sysctl fs.file-max 2>/dev/null || echo "  Unable to read"
    
    echo -e "\n${CYAN}Paqet Config File:${NC}"
    if [ -f "/etc/sysctl.d/99-paqet-tunnel.conf" ]; then
        echo -e "  ${GREEN}Present${NC}: /etc/sysctl.d/99-paqet-tunnel.conf"
    else
        echo -e "  ${YELLOW}Not found${NC}"
    fi
}

# ============================================
# OPTIONS MENU - Edit Tunnel Settings
# ============================================

# Select a tunnel to edit
select_tunnel_for_edit() {
    while true; do
        echo ""
        echo -e "${CYAN}Select a tunnel to edit:${NC}"
        echo ""
        
        local i=1
        local tunnels=()
        local configs=()
        
        for service_file in /etc/systemd/system/paqet-*.service; do
            if [ -f "$service_file" ]; then
                local service_name=$(basename "$service_file" .service)
                local config
                config=$(resolve_service_config_path "$service_file")
                tunnels+=("$service_name")
                configs+=("$config")
                local status=$(systemctl is-active "$service_name" 2>/dev/null || echo "unknown")
                case "$status" in
                    active) echo -e "  ${WHITE}$i)${NC} ${GREEN}●${NC} $service_name" ;;
                    *) echo -e "  ${WHITE}$i)${NC} ${RED}○${NC} $service_name" ;;
                esac
                ((i++))
            fi
        done
        
        if [ ${#tunnels[@]} -eq 0 ]; then
            print_warning "No tunnels found"
            read -p "Press Enter to continue..."
            return
        fi
        
        echo ""
        read -p "Enter tunnel number (or 'back'): " choice
        
        if [ "$choice" = "back" ]; then
            return
        fi
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#tunnels[@]} ]; then
            SELECTED_TUNNEL="${tunnels[$((choice-1))]}"
            SELECTED_CONFIG="${configs[$((choice-1))]}"
            show_tunnel_options
        else
            print_error "Invalid selection"
        fi
    done
}

# Show options for selected tunnel
show_tunnel_options() {
    while true; do
        echo ""
        echo -e "${CYAN}============================================${NC}"
        echo -e "${CYAN}  Options: $SELECTED_TUNNEL${NC}"
        echo -e "${CYAN}============================================${NC}"
        echo -e "  Config: $SELECTED_CONFIG"
        echo ""
        
        # Read current values from config
        if [ -f "$SELECTED_CONFIG" ]; then
            local current_mtu=$(grep "mtu:" "$SELECTED_CONFIG" | head -1 | awk '{print $2}')
            local current_mode=$(grep "mode:" "$SELECTED_CONFIG" | head -1 | sed 's/.*"\(.*\)".*/\1/')
            local current_conn=$(grep "conn:" "$SELECTED_CONFIG" | head -1 | awk '{print $2}')
            local current_port
            current_port=$(extract_tunnel_port_from_config "$SELECTED_CONFIG")
            
            echo -e "  Current Settings:"
            echo -e "    MTU:         ${GREEN}$current_mtu${NC}"
            echo -e "    KCP Mode:    ${GREEN}$current_mode${NC}"
            echo -e "    Connections: ${GREEN}$current_conn${NC}"
            echo -e "    Port:        ${GREEN}$current_port${NC}"
        fi
        
        echo ""
        echo -e "  ${WHITE}1)${NC} Change MTU"
        echo -e "  ${WHITE}2)${NC} Change KCP Mode"
        echo -e "  ${WHITE}3)${NC} Change Connection Count"
        echo -e "  ${WHITE}4)${NC} Change Port"
        echo -e "  ${WHITE}5)${NC} View full config"
        echo -e "  ${WHITE}6)${NC} Back"
        echo ""
        
        local choice=""
        read -p "Enter choice (1-6): " choice
        
        case "$choice" in
            1) edit_mtu ;;
            2) edit_kcp_mode ;;
            3) edit_conn_count ;;
            4) edit_port ;;
            5) view_config ;;
            6) return ;;
            *) ;;
        esac
    done
}

# Edit MTU value
edit_mtu() {
    local current_mtu=$(grep "mtu:" "$SELECTED_CONFIG" | head -1 | awk '{print $2}')
    echo ""
    echo -e "${YELLOW}Current MTU: $current_mtu${NC}"
    echo -e "Recommended values: 1200-1400"
    echo -e "Lower values may help with unstable connections"
    echo ""
    read -p "Enter new MTU value (or 'cancel'): " new_mtu
    
    if [ "$new_mtu" = "cancel" ]; then
        return
    fi
    
    if [[ "$new_mtu" =~ ^[0-9]+$ ]] && [ "$new_mtu" -ge 500 ] && [ "$new_mtu" -le 1500 ]; then
        sed -i "s/mtu: $current_mtu/mtu: $new_mtu/" "$SELECTED_CONFIG"
        print_success "MTU changed to $new_mtu"
        restart_tunnel_after_edit
    else
        print_error "Invalid MTU value (must be 500-1500)"
    fi
}

# Edit KCP mode
edit_kcp_mode() {
    local current_mode=$(grep "mode:" "$SELECTED_CONFIG" | head -1 | sed 's/.*"\(.*\)".*/\1/')
    echo ""
    echo -e "${YELLOW}Current KCP Mode: $current_mode${NC}"
    echo ""
    echo -e "  ${WHITE}1)${NC} fast (Recommended)"
    echo -e "  ${WHITE}2)${NC} fast2 (More aggressive)"
    echo -e "  ${WHITE}3)${NC} fast3 (Most aggressive - very high bandwidth usage)"
    echo -e "  ${WHITE}4)${NC} normal (Conservative)"
    echo -e "  ${WHITE}5)${NC} Cancel"
    echo ""
    read -p "Choose new mode (1-5): " choice
    
    local new_mode=""
    case "$choice" in
        1) new_mode="fast" ;;
        2) new_mode="fast2" ;;
        3) new_mode="fast3" ;;
        4) new_mode="normal" ;;
        5) return ;;
        *) print_error "Invalid choice"; return ;;
    esac
    
    sed -i "s/mode: \"$current_mode\"/mode: \"$new_mode\"/" "$SELECTED_CONFIG"
    print_success "KCP Mode changed to $new_mode"
    restart_tunnel_after_edit
}

# Edit connection count
edit_conn_count() {
    local current_conn=$(grep "conn:" "$SELECTED_CONFIG" | head -1 | awk '{print $2}')
    echo ""
    echo -e "${YELLOW}Current Connection Count: $current_conn${NC}"
    echo -e "Recommended: 1-3 (higher = more overhead, more CPU)"
    echo ""
    read -p "Enter new connection count (or 'cancel'): " new_conn
    
    if [ "$new_conn" = "cancel" ]; then
        return
    fi
    
    if [[ "$new_conn" =~ ^[0-9]+$ ]] && [ "$new_conn" -ge 1 ] && [ "$new_conn" -le 50 ]; then
        sed -i "s/conn: $current_conn/conn: $new_conn/" "$SELECTED_CONFIG"
        print_success "Connection count changed to $new_conn"
        restart_tunnel_after_edit
    else
        print_error "Invalid connection count (must be 1-50)"
    fi
}

# Edit port
edit_port() {
    echo ""
    echo -e "${YELLOW}Changing port requires updating both server and client!${NC}"
    echo -e "${RED}Make sure to update the other side as well.${NC}"
    echo ""
    
    local is_server=false
    local current_port
    current_port=$(extract_tunnel_port_from_config "$SELECTED_CONFIG")
    if [ -z "$current_port" ]; then
        print_error "Could not detect current port from config: $SELECTED_CONFIG"
        return
    fi

    if grep -q "role: \"server\"" "$SELECTED_CONFIG"; then
        is_server=true
        echo -e "Current server port: $current_port"
    else
        echo -e "Current server port (connecting to): $current_port"
    fi
    
    read -p "Enter new port (or 'cancel'): " new_port
    
    if [ "$new_port" = "cancel" ]; then
        return
    fi
    
    if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1 ] && [ "$new_port" -le 65535 ]; then
        if [ "$is_server" = true ]; then
            # Update server port in multiple places
            sed -i "s/:$current_port\"/:$new_port\"/g" "$SELECTED_CONFIG"
            print_success "Server port changed to $new_port"
            print_warning "Don't forget to update the client configuration!"
            
            # Update firewall rules
            print_info "Updating firewall rules..."
            iptables -t raw -D PREROUTING -p tcp --dport "$current_port" -j NOTRACK 2>/dev/null
            iptables -t raw -D OUTPUT -p tcp --sport "$current_port" -j NOTRACK 2>/dev/null
            iptables -t mangle -D OUTPUT -p tcp --sport "$current_port" --tcp-flags RST RST -j DROP 2>/dev/null
            setup_firewall_rules "$new_port"
        else
            sed -i "s/:$current_port\"/:$new_port\"/g" "$SELECTED_CONFIG"
            print_success "Server port changed to $new_port"
        fi
        restart_tunnel_after_edit
    else
        print_error "Invalid port (must be 1-65535)"
    fi
}

# View full config
view_config() {
    echo ""
    echo -e "${CYAN}============================================${NC}"
    echo -e "${CYAN}  Configuration: $SELECTED_CONFIG${NC}"
    echo -e "${CYAN}============================================${NC}"
    echo ""
    cat "$SELECTED_CONFIG"
    echo ""
    read -p "Press Enter to continue..."
}

# Restart tunnel after editing
restart_tunnel_after_edit() {
    echo ""
    read -p "Restart tunnel now to apply changes? (yes/no): " confirm
    confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')
    
    if [ "$confirm" = "yes" ] || [ "$confirm" = "y" ]; then
        print_info "Restarting $SELECTED_TUNNEL..."
        systemctl restart "$SELECTED_TUNNEL"
        if [ $? -eq 0 ]; then
            print_success "$SELECTED_TUNNEL restarted successfully"
        else
            print_error "Failed to restart $SELECTED_TUNNEL"
        fi
    else
        print_warning "Changes saved but tunnel not restarted"
        print_info "Run: sudo systemctl restart $SELECTED_TUNNEL"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Options menu entry point
show_options_menu() {
    select_tunnel_for_edit
}

# ============================================
# REPORTS MENU - View Errors and Logs
# ============================================

show_reports_menu() {
    while true; do
        echo ""
        echo -e "${CYAN}"
        ui_line "═" 60
        echo -e "${WHITE}${ICON_LOGS}  Paqet Reports & Logs${NC}"
        echo -e "${CYAN}"
        ui_line "═" 60
        echo -e "${NC}"
        echo ""
        echo -e "  ${WHITE}1)${NC} View recent errors (all tunnels)"
        echo -e "  ${WHITE}2)${NC} View errors for specific tunnel"
        echo -e "  ${WHITE}3)${NC} View last 50 log lines (all tunnels)"
        echo -e "  ${WHITE}4)${NC} View last 100 log lines (specific tunnel)"
        echo -e "  ${WHITE}5)${NC} Check service status (detailed)"
        echo -e "  ${WHITE}6)${NC} Export logs to file"
        echo -e "  ${WHITE}7)${NC} Back to management menu"
        echo ""
        
        local choice=""
        read -p "👉 Enter choice (1-7): " choice
        
        case "$choice" in
            1) view_all_errors ;;
            2) view_tunnel_errors ;;
            3) view_recent_logs ;;
            4) view_tunnel_logs ;;
            5) view_detailed_status ;;
            6) export_logs ;;
            7) return ;;
            *) ;;
        esac
    done
}

# View all errors from all tunnels
view_all_errors() {
    print_header "Recent Errors (All Tunnels)"
    
    local services=""
    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            local service_name=$(basename "$service_file" .service)
            services="$services -u $service_name"
        fi
    done
    
    if [ -z "$services" ]; then
        print_warning "No paqet tunnels found"
    else
        echo -e "${YELLOW}Showing errors from the last 24 hours:${NC}"
        echo ""
        journalctl $services --since "24 hours ago" -p err --no-pager 2>/dev/null || echo "No errors found"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# View errors for specific tunnel
view_tunnel_errors() {
    echo ""
    echo -e "${CYAN}Select a tunnel to view errors:${NC}"
    echo ""
    
    local i=1
    local tunnels=()
    
    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            local service_name=$(basename "$service_file" .service)
            tunnels+=("$service_name")
            echo -e "  ${WHITE}$i)${NC} $service_name"
            ((i++))
        fi
    done
    
    if [ ${#tunnels[@]} -eq 0 ]; then
        print_warning "No tunnels found"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo ""
    read -p "Enter tunnel number (or 'back'): " choice
    
    if [ "$choice" = "back" ]; then
        return
    fi
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#tunnels[@]} ]; then
        local tunnel="${tunnels[$((choice-1))]}"
        print_header "Errors: $tunnel"
        echo -e "${YELLOW}Showing errors from the last 7 days:${NC}"
        echo ""
        journalctl -u "$tunnel" --since "7 days ago" -p err --no-pager 2>/dev/null || echo "No errors found"
    else
        print_error "Invalid selection"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# View recent logs for all tunnels
view_recent_logs() {
    print_header "Recent Logs (All Tunnels - Last 50 lines)"
    
    local services=""
    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            local service_name=$(basename "$service_file" .service)
            services="$services -u $service_name"
        fi
    done
    
    if [ -z "$services" ]; then
        print_warning "No paqet tunnels found"
    else
        journalctl $services -n 50 --no-pager
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# View logs for specific tunnel
view_tunnel_logs() {
    echo ""
    echo -e "${CYAN}Select a tunnel to view logs:${NC}"
    echo ""
    
    local i=1
    local tunnels=()
    
    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            local service_name=$(basename "$service_file" .service)
            tunnels+=("$service_name")
            echo -e "  ${WHITE}$i)${NC} $service_name"
            ((i++))
        fi
    done
    
    if [ ${#tunnels[@]} -eq 0 ]; then
        print_warning "No tunnels found"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo ""
    read -p "Enter tunnel number (or 'back'): " choice
    
    if [ "$choice" = "back" ]; then
        return
    fi
    
    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le ${#tunnels[@]} ]; then
        local tunnel="${tunnels[$((choice-1))]}"
        print_header "Logs: $tunnel (Last 100 lines)"
        journalctl -u "$tunnel" -n 100 --no-pager
    else
        print_error "Invalid selection"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# View detailed status
view_detailed_status() {
    print_header "Detailed Service Status"
    
    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            local service_name=$(basename "$service_file" .service)
            echo -e "${CYAN}--- $service_name ---${NC}"
            systemctl status "$service_name" --no-pager 2>/dev/null | head -20
            echo ""
        fi
    done
    
    read -p "Press Enter to continue..."
}

# Export logs to file
export_logs() {
    local export_dir="/var/log/paqet"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local export_file="$export_dir/paqet_logs_$timestamp.txt"
    
    mkdir -p "$export_dir"
    
    print_header "Exporting Logs"
    
    echo "=== Paqet Tunnel Logs ===" > "$export_file"
    echo "Exported: $(date)" >> "$export_file"
    echo "" >> "$export_file"
    
    for service_file in /etc/systemd/system/paqet-*.service; do
        if [ -f "$service_file" ]; then
            local service_name=$(basename "$service_file" .service)
            echo "=== $service_name ===" >> "$export_file"
            echo "" >> "$export_file"
            
            echo "--- Status ---" >> "$export_file"
            systemctl status "$service_name" --no-pager 2>/dev/null >> "$export_file"
            echo "" >> "$export_file"
            
            echo "--- Last 200 log lines ---" >> "$export_file"
            journalctl -u "$service_name" -n 200 --no-pager 2>/dev/null >> "$export_file"
            echo "" >> "$export_file"
            
            echo "--- Errors (last 7 days) ---" >> "$export_file"
            journalctl -u "$service_name" --since "7 days ago" -p err --no-pager 2>/dev/null >> "$export_file"
            echo "" >> "$export_file"
        fi
    done
    
    print_success "Logs exported to: $export_file"
    print_info "File size: $(du -h "$export_file" | cut -f1)"
    
    echo ""
    read -p "Press Enter to continue..."
}

# Handle command line arguments for management
handle_cli_args() {
    case "$1" in
        --status|--list)
            check_root
            list_tunnels
            exit 0
            ;;
        --start-all)
            check_root
            start_all_tunnels
            exit 0
            ;;
        --stop-all)
            check_root
            stop_all_tunnels
            exit 0
            ;;
        --restart-all)
            check_root
            restart_all_tunnels
            exit 0
            ;;
        --monitor)
            check_root
            monitor_tunnels
            exit 0
            ;;
        --remove)
            check_root
            remove_tunnel "$2"
            exit 0
            ;;
        --manage)
            check_root
            show_management_menu
            exit 0
            ;;
        --options)
            check_root
            show_options_menu
            exit 0
            ;;
        --reports|--logs)
            check_root
            show_reports_menu
            exit 0
            ;;
        --errors)
            check_root
            view_all_errors
            exit 0
            ;;
        --update-core|--update)
            update_paqet_core
            exit $?
            ;;
        --install)
            check_root
            install_to_bin
            exit 0
            ;;
        --uninstall)
            check_root
            uninstall_from_bin
            exit 0
            ;;
        --optimize)
            check_root
            optimize_kernel_settings
            exit 0
            ;;
        --help|-h)
            echo ""
            echo -e "${CYAN}"
            ui_line "═" 60
            echo -e "${WHITE}${ICON_MENU}  Paqet Tunnel Deployment Script${NC}"
            echo -e "${CYAN}"
            ui_line "═" 60
            echo -e "${NC}"
            echo ""
            echo "Usage: sudo ./deploy.sh [OPTION]"
            echo "   or: sudo paqet [OPTION]  (if installed)"
            echo ""
            echo "Options:"
            echo "  --status, --list    List all tunnels and their status"
            echo "  --start-all         Start all tunnels"
            echo "  --stop-all          Stop all tunnels"
            echo "  --restart-all       Restart all tunnels"
            echo "  --monitor           Monitor all tunnels (live logs)"
            echo "  --remove            Remove a tunnel"
            echo "  --manage            Open management menu"
            echo "  --options           Open options menu (edit settings)"
            echo "  --reports, --logs   Open reports menu"
            echo "  --errors            View recent errors"
            echo "  --optimize          Apply kernel/OS optimizations for tunneling"
            echo "  --update-core       Download and install latest paqet core binary"
            echo "  --update            Alias for --update-core"
            echo "  --install           Install script to /usr/local/bin (run as 'paqet')"
            echo "  --uninstall         Remove script from /usr/local/bin"
            echo "  --help, -h          Show this help"
            echo ""
            echo -e "${DIM}Tip: use the interactive wizard for the best experience: sudo ./deploy.sh${NC}"
            echo ""
            exit 0
            ;;
    esac
}

# Check for CLI management commands first
if [[ $# -gt 0 ]]; then
    case "$1" in
        --status|--list|--start-all|--stop-all|--restart-all|--monitor|--remove|--manage|--options|--reports|--logs|--errors|--optimize|--update-core|--update|--install|--uninstall|--help|-h)
            handle_cli_args "$@"
            ;;
        --*)
            print_error "Unknown option: $1"
            echo ""
            echo "Use --help to see available options"
            exit 1
            ;;
        *)
            # Non-flag arguments also treated as unknown
            print_error "Unknown option: $1"
            echo ""
            echo "Use --help to see available options"
            exit 1
            ;;
    esac
fi

# Run main menu
show_main_menu
