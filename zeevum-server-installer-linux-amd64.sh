#!/bin/bash

APP_USER="zeevum-server"
INSTALL_DIR="/opt/zeevum-server"
CONFIG_DIR="/etc/zeevum-server"
DATA_DIR="/var/lib/zeevum-server"
SERVICE_FILE="/etc/systemd/system/zeevum-server.service"
ENV_FILE="$CONFIG_DIR/zeevum-server.env"
BIN_FILE="$INSTALL_DIR/Zeevum-server"

REQUIRED_VARS=("TLS_CERT_PATH" "TLS_KEY_PATH")

DOWNLOAD_URL="https://github.com/Zeevum/Zeevum-server/releases/latest/download/Zeevum-server-linux-amd64.tar.gz"
CHANNEL_LABEL="stable"

if [ "$1" == "--pre-release" ] || [ "$1" == "--tag" ]; then
    MODE="$1"
    if [ -z "$2" ]; then
        echo "Usage: $0 ${MODE} <tag>   (example: $0 --pre-release v0.2.0-rc.1)" >&2
        exit 1
    fi
    RELEASE_TAG="$2"
    case "$RELEASE_TAG" in
        v*) : ;;
        *) echo "Tag must start with 'v' (got: ${RELEASE_TAG})" >&2; exit 1 ;;
    esac
    DOWNLOAD_URL="https://github.com/Zeevum/Zeevum-server/releases/download/${RELEASE_TAG}/Zeevum-server-linux-amd64.tar.gz"
    CHANNEL_LABEL="${RELEASE_TAG}"
    if [ "$MODE" == "--pre-release" ]; then
        CHANNEL_LABEL="PRE-RELEASE ${RELEASE_TAG} (testing build)"
    fi
fi

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

print_message() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

grant_cert_access() {
    local file_path="$1"
    local real_path=$(readlink -f "$file_path")

    if ! command -v setfacl &> /dev/null; then
        print_error "'setfacl' package not found. Installing with: apt install acl -y..."
        apt install acl -y
    fi

    setfacl -m u:"$APP_USER":r "$real_path" 2>/dev/null || {
        print_error "Cannot grant rights for file: $real_path"
        exit 1
    }

    local dir_path=$(dirname "$real_path")
    while [ "$dir_path" != "/" ]; do
        setfacl -m u:"$APP_USER":x "$dir_path" 2>/dev/null || {
            print_error "Cannot grant rights for directory: $dir_path"
            exit 1
        }
        dir_path=$(dirname "$dir_path")
    done
}

if [ "$1" == "--remove" ]; then
    print_warning "Deleting Zeevum-server..."
    
    systemctl stop zeevum-server 2>/dev/null
    systemctl disable zeevum-server 2>/dev/null
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    rm -rf "$INSTALL_DIR"
    
    printf "%s[?]%s Do you want to delete configs, database and settings? (y/n): " "$YELLOW" "$NC"
    read del_data
    if [[ "$del_data" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR" "$DATA_DIR"
        userdel "$APP_USER" 2>/dev/null
        print_message "Zeevum-server deleted completely."
    else
        print_message "Zeevum-server deleted. Configs and settings saved in $DATA_DIR and $CONFIG_DIR"
    fi
    exit 0
fi

if [ "$EUID" -ne 0 ]; then
    print_error "Please run this script using: sudo bash zeevum-server-installer.sh"
    exit 1
fi

if [ -f "$SERVICE_FILE" ]; then
    print_warning "Zeevum-server is already installed. Starting UPDATE mode..."
    
    for var in "${REQUIRED_VARS[@]}"; do
        if ! grep -q "^${var}=." "$ENV_FILE"; then
            print_warning "New required variable detected: $var"
            
            if [[ "$var" == *"PATH"* ]]; then
                while true; do
                    printf "%s[?]%s Enter path for %s: " "$YELLOW" "$NC" "$var"
                    read val
                    if [ -f "$val" ]; then
                        grant_cert_access "$val"
                        break
                    else
                        print_error "File not found. Try again."
                    fi
                done
            else
                printf "%s[?]%s Enter value for %s: " "$YELLOW" "$NC" "$var"
                read val
            fi
            echo "${var}=${val}" >> "$ENV_FILE"
            print_message "Added $var to $ENV_FILE"
        fi
    done

    print_message "Backfilling missing default variables..."
    DEFAULT_VARS=("SESSION_DURATION_HOURS=720" "LOG_LEVEL=Info")
    for kv in "${DEFAULT_VARS[@]}"; do
        var="${kv%%=*}"
        if ! grep -q "^${var}=" "$ENV_FILE"; then
            echo "$kv" >> "$ENV_FILE"
            print_message "Added $kv to $ENV_FILE"
        fi
    done

    print_message "Verifying certificate permissions..."
    CURRENT_CERT=$(grep "^TLS_CERT_PATH=" "$ENV_FILE" | cut -d'=' -f2)
    CURRENT_KEY=$(grep "^TLS_KEY_PATH=" "$ENV_FILE" | cut -d'=' -f2)
    
    if [ -n "$CURRENT_CERT" ] && [ -f "$CURRENT_CERT" ]; then
        grant_cert_access "$CURRENT_CERT"
    fi
    if [ -n "$CURRENT_KEY" ] && [ -f "$CURRENT_KEY" ]; then
        grant_cert_access "$CURRENT_KEY"
    fi
    print_message "Certificate permissions verified."

    print_message "Stopping service for update..."
    systemctl stop zeevum-server
    
    print_message "Backing up old binary..."
    cp "$BIN_FILE" "${BIN_FILE}.bak"
    
    print_message "Downloading ${CHANNEL_LABEL}..."
    if ! command -v wget &> /dev/null; then
        print_error "'wget' package not found. Installing..."
        apt install wget -y
    fi
    
    wget -qO /tmp/zeevum-server.tar.gz "$DOWNLOAD_URL"
    if [ $? -ne 0 ]; then
        print_error "Error while downloading. Check URL: $DOWNLOAD_URL"
        rm -f /tmp/zeevum-server.tar.gz
        exit 1
    fi
    
    tar -xzf /tmp/zeevum-server.tar.gz -C "$INSTALL_DIR"
    rm /tmp/zeevum-server.tar.gz
    
    if [ ! -f "$BIN_FILE" ]; then
        BIN_FILE=$(find "$INSTALL_DIR" -type f -name "Zeevum-server" | head -n 1)
    fi
    
    if [ -z "$BIN_FILE" ]; then
        print_error "Zeevum-server binary file not found in archive! Restoring backup."
        mv "${BIN_FILE}.bak" "$BIN_FILE"
        exit 1
    fi
    
    chmod +x "$BIN_FILE"
    chown -R "$APP_USER":"$APP_USER" "$INSTALL_DIR"
    
    print_message "Starting updated service..."
    systemctl start zeevum-server
    sleep 3
    
    if systemctl is-active --quiet zeevum-server; then
        print_message "Update complete! Backup removed."
        rm -f "${BIN_FILE}.bak"
    else
        print_error "Service failed to start after update!"
        print_error "Restoring previous binary..."
        mv "${BIN_FILE}.bak" "$BIN_FILE"
        systemctl start zeevum-server
        print_warning "Rolled back to previous version. Please check logs: journalctl -u zeevum-server -e"
    fi
    exit 0
fi

print_message "Installing Zeevum-server..."

if id "$APP_USER" &>/dev/null; then
    print_warning "User $APP_USER already exists. Skipping creating new user."
else
    useradd -r -s /bin/false "$APP_USER"
    print_message "Created system user: $APP_USER."
fi

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$DATA_DIR"

echo -e "${CYAN}=== Server settings ===${NC}"

while true; do
    printf "%s[?]%s Enter path to .crt file of domain (TLS_CERT_PATH): " "$YELLOW" "$NC"
    read tls_cert
    if [ -f "$tls_cert" ]; then break; else print_error "File .crt not found. Try again."; fi
done

while true; do
    printf "%s[?]%s Enter path to .crt.key file of domain (TLS_KEY_PATH): " "$YELLOW" "$NC"
    read tls_key
    if [ -f "$tls_key" ]; then break; else print_error "File .crt.key not found. Try again."; fi
done

printf "%s[?]%s Hours before user session expires [720]: " "$YELLOW" "$NC"
read session_duration_hours
session_duration_hours=${session_duration_hours:-"720"}

printf "%s[?]%s PoW difficulty (weak, medium or strong) [medium]: " "$YELLOW" "$NC"
read pow_difficulty
pow_difficulty=${pow_difficulty:-"medium"}

printf "%s[?]%s Server address:port [0.0.0.0:1990]: " "$YELLOW" "$NC"
read server_addr
server_addr=${server_addr:-"0.0.0.0:1990"}

printf "%s[?]%s Path where DB will be placed [/var/lib/zeevum-server/database.sqlite]: " "$YELLOW" "$NC"
read db_path
db_path=${db_path:-"/var/lib/zeevum-server/database.sqlite"}

printf "%s[?]%s Read timeout [300]: " "$YELLOW" "$NC"
read read_timeout
read_timeout=${read_timeout:-"300"}

printf "%s[?]%s Handshake timeout [10]: " "$YELLOW" "$NC"
read handshake_timeout
handshake_timeout=${handshake_timeout:-"10"}

print_message "Setting up rights to read .crt and .crt.key files for $APP_USER..."
grant_cert_access "$tls_cert"
grant_cert_access "$tls_key"
print_message "Rights to read .crt and .crt.key successfully granted"

print_message "Config generating... $ENV_FILE"
cat <<EOF > "$ENV_FILE"
POW_DIFFICULTY=$pow_difficulty
SERVER_ADDRESS=$server_addr
DB_PATH=$db_path
READ_TIMEOUT=$read_timeout
HANDSHAKE_TIMEOUT=$handshake_timeout
SESSION_DURATION_HOURS=$session_duration_hours
LOG_LEVEL=Info
TLS_CERT_PATH=$tls_cert
TLS_KEY_PATH=$tls_key
HOME=$DATA_DIR
XDG_DATA_HOME=$DATA_DIR
EOF
chmod 640 "$ENV_FILE"
chown root:"$APP_USER" "$ENV_FILE"

print_message "Downloading ${CHANNEL_LABEL} release of server from GitHub..."
if ! command -v wget &> /dev/null; then
    print_error "'wget' package not found. Installing with: apt install wget -y"
    apt install wget -y
fi

wget -qO /tmp/zeevum-server.tar.gz "$DOWNLOAD_URL"
if [ $? -ne 0 ]; then
    print_error "Error while downloading. Check URL: $DOWNLOAD_URL"
    exit 1
fi

tar -xzf /tmp/zeevum-server.tar.gz -C "$INSTALL_DIR"
rm /tmp/zeevum-server.tar.gz

if [ ! -f "$BIN_FILE" ]; then
    BIN_FILE=$(find "$INSTALL_DIR" -type f -name "Zeevum-server" | head -n 1)
fi

if [ -z "$BIN_FILE" ]; then
    print_error "Zeevum-server binary file not found!"
    exit 1
fi

chmod +x "$BIN_FILE"
chown -R "$APP_USER":"$APP_USER" "$INSTALL_DIR"
chown -R "$APP_USER":"$APP_USER" "$DATA_DIR"

print_message "Creating systemd service..."
cat <<EOF > "$SERVICE_FILE"
[Unit]
Description=Zeevum Server
After=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
EnvironmentFile=$ENV_FILE
ExecStart=$BIN_FILE
Restart=on-failure
RestartSec=5s

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable zeevum-server
systemctl start zeevum-server

print_message "Installation complete!"
echo -e "${CYAN}========================================${NC}"
systemctl status zeevum-server --no-pager
echo -e "${CYAN}========================================${NC}"
print_warning "If the service did not launch, check logs: journalctl -u zeevum-server -e"