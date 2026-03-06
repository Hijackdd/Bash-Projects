#!/bin/bash

# ============================================
# Student name: Matan Ohayon / S22
# Class code: TMagen773637
# Lecturer name: Eliran Berkovich / Erel Regev
# ============================================


# ====== Colors declared as variable ======
BOLD_GREEN='\033[1m\033[32m'
BOLD_RED='\033[1m\033[31m'
BOLD_YELLOW='\033[1m\033[33m'
NC='\033[0m' # No Color
# =====================================

# ====== Wordlists options ======
WORDLIST_REPO="https://github.com/Hijackdd/Bash-Projects.git"
USERLIST="/usr/share/wordlists/usernames.txt"
PASSLIST="/usr/share/wordlists/passwords.txt"
BUILTIN_PASSLIST_NAME="builtin_passwords.lst"
# =====================================

# ====== Output folder names ======
HOST_SCAN_DIR="Target_Host_Scan"
SERVICE_ENUM_DIR="Service_Credential_Enumeration"
VULN_DIR="Vulnerability_Mapping"
# =====================================

# ====== Network range templates ======
CIDR_PATTERN='^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$'
WILDCARD_PATTERN='^([0-9]{1,3}\.){3}\*$'
RANGE_PATTERN='^([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}$'
FULL_RANGE_PATTERN='^([0-9]{1,3}\.){3}[0-9]{1,3}-([0-9]{1,3}\.){3}[0-9]{1,3}$'
# =====================================

# ====== GUI Loader - Spinner ======
function SPINNER_LOADER() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    echo -ne "${BOLD_RED}Scanning in process... ${NC}"
    while kill -0 "$pid" 2>/dev/null; do
        for (( i=0; i<${#spinstr}; i++ )); do
            printf "\r${BOLD_RED}Scanning in process... %s${NC}" "${spinstr:i:1}"
            sleep $delay
        done
    done
    printf "\r"
}
# =====================================

# ====== Checking for required tools ======
function CHECK_TOOLS() {
    local scan_type=$1
    local tools=()

    if [[ "$scan_type" == "basic" ]]; then
        tools=("nmap" "hydra" "masscan" "git")
    elif [[ "$scan_type" == "full" ]]; then
        tools=("nmap" "hydra" "masscan" "git" "searchsploit" "nikto")
    else
        echo -e "${BOLD_RED}Unknown scan type: $scan_type${NC}"
        return 1
    fi

    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${BOLD_YELLOW}Tool '$tool' is NOT installed.${NC}"
            read -p "Do you want to attempt to install '$tool'? (y/n): " answer
            if [[ "$answer" =~ ^[Yy]$ ]]; then
                echo "Installing $tool..."
                sudo apt-get update -qq &> /dev/null
                if ! sudo apt-get install -y "$tool" &> /dev/null; then
                    echo -e "${BOLD_RED}Failed to install $tool. Continuing but may fail later.${NC}"
                else
                    echo -e "${BOLD_GREEN}$tool installed successfully.${NC}"
                fi
            else
                echo -e "${BOLD_YELLOW}Continuing without $tool. Some features may be skipped.${NC}"
            fi
        fi
    done

    echo -e "${BOLD_GREEN}Tool check completed for $scan_type scan.${NC}"
    return 0
}
# =====================================

# ====== Wordlist selection function ======
function SELECT_WORDLISTS() {
    local SCAN_DIR=$1

    echo -e "\n${BOLD_GREEN}Wordlist Selection:${NC}"
    echo "1) Use default wordlists (tries common locations, else creates builtin lists)"
    echo "2) Download custom wordlists from repository"
    echo "3) Specify custom wordlist paths"
    echo -ne "${BOLD_GREEN}Enter choice [1-3]: ${NC}"
    read WORDLIST_CHOICE

    case $WORDLIST_CHOICE in
        1)
            # Use default Nmap/seclist paths or create builtin lists
            echo -e "${BOLD_GREEN}Using default/builtin wordlists...${NC}"

            DEFAULT_USER_PATHS=(
                "/usr/share/nmap/nselib/data/usernames.lst"
                "/usr/share/wordlists/nmap/usernames.txt"
                "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
                "/usr/share/wordlists/dirb/others/names.txt"
            )

            DEFAULT_PASS_PATHS=(
                "/usr/share/nmap/nselib/data/passwords.lst"
                "/usr/share/wordlists/nmap/passwords.txt"
                "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt"
                "/usr/share/wordlists/rockyou.txt"
                "/usr/share/wordlists/dirb/others/best110.txt"
            )

            USERLIST=""
            for path in "${DEFAULT_USER_PATHS[@]}"; do
                if [[ -f "$path" ]]; then
                    USERLIST="$path"
                    echo -e "${BOLD_GREEN}Found username wordlist: $path${NC}"
                    break
                fi
            done

            PASSLIST=""
            for path in "${DEFAULT_PASS_PATHS[@]}"; do
                if [[ -f "$path" ]]; then
                    PASSLIST="$path"
                    echo -e "${BOLD_GREEN}Found password wordlist: $path${NC}"
                    break
                fi
            done

            mkdir -p "$SCAN_DIR/Wordlists" &> /dev/null
            if [[ -z "$USERLIST" ]]; then
                # create a small username list
                USERLIST="$SCAN_DIR/Wordlists/default_usernames.txt"
                cat > "$USERLIST" << 'EOF'
admin
root
user
test
guest
ubuntu
pi
oracle
postgres
EOF
                echo -e "${BOLD_YELLOW}Created builtin username list at $USERLIST${NC}"
            fi
            if [[ -z "$PASSLIST" ]]; then
                PASSLIST="$SCAN_DIR/Wordlists/$BUILTIN_PASSLIST_NAME"
                cat > "$PASSLIST" << 'EOF'
123456
password
admin
12345678
qwerty
letmein
changeme
welcome
password123
EOF
                echo -e "${BOLD_YELLOW}Created builtin password list at $PASSLIST${NC}"
            fi
            ;;
        2)
            echo -e "${BOLD_GREEN}Downloading wordlists from $WORDLIST_REPO ...${NC}"
            mkdir -p "$SCAN_DIR/Wordlists" &> /dev/null
            if [ -d "$SCAN_DIR/Wordlists/.git" ]; then
                rm -rf "$SCAN_DIR/Wordlists"
                mkdir -p "$SCAN_DIR/Wordlists"
            fi
            git clone "$WORDLIST_REPO" "$SCAN_DIR/Wordlists" &> /dev/null &
            SPINNER_LOADER $!
            wait $!
            echo -e "${BOLD_GREEN}Wordlists saved to $SCAN_DIR/Wordlists${NC}"
            USERLIST="$SCAN_DIR/Wordlists/usernames.txt"
            PASSLIST="$SCAN_DIR/Wordlists/passwords.txt"
            if [[ ! -f "$USERLIST" || ! -f "$PASSLIST" ]]; then
                echo -e "${BOLD_RED}Expected wordlists not found inside repo. Exiting.${NC}"
                exit 1
            fi
            ;;
        3)
            echo -e "${BOLD_GREEN}Specify custom wordlist paths:${NC}"
            while true; do
                echo -ne "${BOLD_GREEN}Enter username wordlist path: ${NC}"
                read -e CUSTOM_USERLIST
                CUSTOM_USERLIST="${CUSTOM_USERLIST/#\~/$HOME}"
                if [[ -f "$CUSTOM_USERLIST" ]]; then
                    USERLIST="$CUSTOM_USERLIST"
                    echo -e "${BOLD_GREEN}Username wordlist: $USERLIST ($(wc -l < "$USERLIST") lines)${NC}"
                    break
                else
                    echo -e "${BOLD_RED}File not found: $CUSTOM_USERLIST. Please try again.${NC}"
                fi
            done

            while true; do
                echo -ne "${BOLD_GREEN}Enter password wordlist path: ${NC}"
                read -e CUSTOM_PASSLIST
                CUSTOM_PASSLIST="${CUSTOM_PASSLIST/#\~/$HOME}"
                if [[ -f "$CUSTOM_PASSLIST" ]]; then
                    PASSLIST="$CUSTOM_PASSLIST"
                    echo -e "${BOLD_GREEN}Password wordlist: $PASSLIST ($(wc -l < "$PASSLIST") lines)${NC}"
                    break
                else
                    echo -e "${BOLD_RED}File not found: $CUSTOM_PASSLIST. Please try again.${NC}"
                fi
            done
            ;;
        *)
            echo -e "${BOLD_RED}Invalid option. Please try again.${NC}"
            SELECT_WORDLISTS "$SCAN_DIR"
            ;;
    esac

    echo -e "${BOLD_GREEN}Selected wordlists:${NC}"
    echo "  Username: $USERLIST"
    echo "  Password: $PASSLIST"
}
# =====================================

# ====== Service Detection Function ======
function CHECK_SERVICE() {
    local HOST=$1
    local PORT=$2

    if nmap -p "$PORT" "$HOST" --host-timeout 10s -oG - 2>/dev/null | grep -q "$PORT/open"; then
        return 0
    else
        return 1
    fi
}
# =====================================

# ====== Hydra ======
function RUN_HYDRA() {
    local MODULE="$1"
    local TARGET_URI="$2"
    local OUTFILE_RAW="$3"
    timeout 300 hydra -L "$USERLIST" -P "$PASSLIST" -t 4 -f "$MODULE" > "$OUTFILE_RAW" 2>&1 || true
}
# =====================================

# ====== Basic Scan Function ======
function BASIC_SCAN() {
    local TIMESTAMP="$(date +%F_%H-%M-%S)"
    local SCAN_DIR="$MAIN_DIR/basic_scan_$TIMESTAMP"

    mkdir -p "$SCAN_DIR/$HOST_SCAN_DIR" &> /dev/null
    mkdir -p "$SCAN_DIR/$SERVICE_ENUM_DIR" &> /dev/null

    SELECT_WORDLISTS "$SCAN_DIR"

    echo -e "\n${BOLD_GREEN}Performing ping scan to find live hosts...${NC}"
    LOCAL_IPS=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -vE '^(127|169\.254)\.' | tr '\n' '|' | sed 's/|$//')

    nmap -sn "$TARGET" -oG - 2>/dev/null | grep -i "Status: Up" | awk '{print $2}' | \
        grep -Ev '(\.1$|\.254$)' | grep -Ev "$LOCAL_IPS" > "$SCAN_DIR/$HOST_SCAN_DIR/live_hosts.txt"

    LIVE_HOST_FILE="$SCAN_DIR/$HOST_SCAN_DIR/live_hosts.txt"
    if [[ ! -s "$LIVE_HOST_FILE" ]]; then
        echo -e "${BOLD_RED}No live hosts found. Exiting scan.${NC}"
        exit 1
    fi

    LIVE_HOST_COUNT=$(wc -l < "$LIVE_HOST_FILE")
    echo -e "${BOLD_GREEN}Found $LIVE_HOST_COUNT live hosts${NC}"

    echo -e "${BOLD_GREEN}Running basic scan against live hosts - Nmap TCP Scan${NC}"
    nmap -sT -sV -p- --max-retries 1 --host-timeout 300s -iL "$LIVE_HOST_FILE" -oN "$SCAN_DIR/$HOST_SCAN_DIR/nmap_tcp_scan.txt" &> /dev/null &
    SPINNER_LOADER $!
    wait $!
    echo -e "${BOLD_GREEN}TCP scan completed${NC}"

    echo -e "${BOLD_GREEN}Running UDP scan via Masscan on live hosts (top 1000 ports)${NC}"
    if command -v masscan &> /dev/null; then
        sudo masscan -pU:1-1000 -iL "$LIVE_HOST_FILE" --rate 1000 -oL "$SCAN_DIR/$HOST_SCAN_DIR/masscan_udp_scan.txt" &> /dev/null &
        SPINNER_LOADER $!
        wait $!
        cp "$SCAN_DIR/$HOST_SCAN_DIR/masscan_udp_scan.txt" "$SCAN_DIR/$HOST_SCAN_DIR/masscan_udp_result.txt" &> /dev/null
        echo -e "${BOLD_GREEN}UDP scan completed${NC}"
    else
        echo -e "${BOLD_RED}Masscan not available, skipping UDP scan${NC}"
    fi

    echo -e "\n${BOLD_GREEN}Starting credential enumeration against detected services...${NC}"
    echo -e "${BOLD_GREEN}Using wordlists:${NC}"
    echo "  Usernames: $USERLIST ($(wc -l < "$USERLIST" 2>/dev/null || echo "0") entries)"
    echo "  Passwords: $PASSLIST ($(wc -l < "$PASSLIST" 2>/dev/null || echo "0") entries)"

    while read -r HOST; do
        HOST_DIR="$SCAN_DIR/$SERVICE_ENUM_DIR/$HOST"
        mkdir -p "$HOST_DIR"
        echo -e "\n${BOLD_GREEN}Processing host: $HOST${NC}"

        # SSH Service checking & Brute-forcing
        if CHECK_SERVICE "$HOST" 22; then
            echo -e "${BOLD_GREEN}  SSH detected - starting brute-force...${NC}"
            RUN_HYDRA "ssh://$HOST" "ssh://$HOST" "$HOST_DIR/hydra_ssh_raw.txt"
            # process results
            {
                echo "=== SSH Brute-Force Results for $HOST ==="
                echo "Date: $(date)"
                echo ""
                if grep -q "\[22\]\[ssh\] host:" "$HOST_DIR/hydra_ssh_raw.txt" 2>/dev/null; then
                    grep "\[22\]\[ssh\] host:" "$HOST_DIR/hydra_ssh_raw.txt" | sed 's/^/  /'
                else
                    echo "No successful SSH logins found."
                fi
                echo ""
                echo "Raw Hydra Output:"
                cat "$HOST_DIR/hydra_ssh_raw.txt" 2>/dev/null || true
            } > "$HOST_DIR/hydra_ssh.txt"
            rm -f "$HOST_DIR/hydra_ssh_raw.txt"
        else
            echo "  [INFO] SSH not detected on $HOST"
        fi

        # FTP Service checking & Brute-forcing
        if CHECK_SERVICE "$HOST" 21; then
            echo -e "${BOLD_GREEN}  FTP detected - starting brute-force...${NC}"
            RUN_HYDRA "ftp://$HOST" "ftp://$HOST" "$HOST_DIR/hydra_ftp_raw.txt"
            {
                echo "=== FTP Brute-Force Results for $HOST ==="
                echo "Date: $(date)"
                echo ""
                if grep -q "\[21\]\[ftp\] host:" "$HOST_DIR/hydra_ftp_raw.txt" 2>/dev/null; then
                    grep "\[21\]\[ftp\] host:" "$HOST_DIR/hydra_ftp_raw.txt" | sed 's/^/  /'
                else
                    echo "No successful FTP logins found."
                fi
                echo ""
                echo "Raw Hydra Output:"
                cat "$HOST_DIR/hydra_ftp_raw.txt" 2>/dev/null || true
            } > "$HOST_DIR/hydra_ftp.txt"
            rm -f "$HOST_DIR/hydra_ftp_raw.txt"
        else
            echo "  [INFO] FTP not detected on $HOST"
        fi

        # Telnet Service checking & Brute-forcing
        if CHECK_SERVICE "$HOST" 23; then
            echo -e "${BOLD_GREEN}  Telnet detected - starting brute-force...${NC}"
            RUN_HYDRA "telnet://$HOST" "telnet://$HOST" "$HOST_DIR/hydra_telnet_raw.txt"
            {
                echo "=== TELNET Brute-Force Results for $HOST ==="
                echo "Date: $(date)"
                echo ""
                if grep -q "\[23\]\[telnet\] host:" "$HOST_DIR/hydra_telnet_raw.txt" 2>/dev/null; then
                    grep "\[23\]\[telnet\] host:" "$HOST_DIR/hydra_telnet_raw.txt" | sed 's/^/  /'
                else
                    echo "No successful TELNET logins found."
                fi
                echo ""
                echo "Raw Hydra Output:"
                cat "$HOST_DIR/hydra_telnet_raw.txt" 2>/dev/null || true
            } > "$HOST_DIR/hydra_telnet.txt"
            rm -f "$HOST_DIR/hydra_telnet_raw.txt"
        else
            echo "  [INFO] Telnet not detected on $HOST"
        fi

        # RDP Service checking & Brute-forcing
        if CHECK_SERVICE "$HOST" 3389; then
            echo -e "${BOLD_GREEN}  RDP detected - starting brute-force...${NC}"
            RUN_HYDRA "rdp://$HOST" "rdp://$HOST" "$HOST_DIR/hydra_rdp_raw.txt"
            {
                echo "=== RDP Brute-Force Results for $HOST ==="
                echo "Date: $(date)"
                echo ""
                if grep -q "\[3389\]\[rdp\] host:" "$HOST_DIR/hydra_rdp_raw.txt" 2>/dev/null; then
                    grep "\[3389\]\[rdp\] host:" "$HOST_DIR/hydra_rdp_raw.txt" | sed 's/^/  /'
                else
                    echo "No successful RDP logins found."
                fi
                echo ""
                echo "Raw Hydra Output:"
                cat "$HOST_DIR/hydra_rdp_raw.txt" 2>/dev/null || true
            } > "$HOST_DIR/hydra_rdp.txt"
            rm -f "$HOST_DIR/hydra_rdp_raw.txt"
        else
            echo "  [INFO] RDP not detected on $HOST"
        fi

    done < "$LIVE_HOST_FILE"

    echo -e "\n${BOLD_GREEN}Basic scan completed. Results saved in:${NC} $SCAN_DIR"
    echo -e "${BOLD_GREEN}Check the following directories for results:${NC}"
    echo "  - Host discovery: $SCAN_DIR/$HOST_SCAN_DIR/"
    echo "  - Service enumeration: $SCAN_DIR/$SERVICE_ENUM_DIR/"
    
    GENERATE_REPORT "$SCAN_DIR" # ADDED REPORT GENERATION
    POST_SCAN_MENU "$SCAN_DIR"
}
# =====================================

# ====== Full Scan Function (NSE + Vuln mapping + Weak creds) ======
function FULL_SCAN() {
    local TIMESTAMP="$(date +%F_%H-%M-%S)"
    local SCAN_DIR="$MAIN_DIR/full_scan_$TIMESTAMP"

    mkdir -p "$SCAN_DIR/$HOST_SCAN_DIR" &> /dev/null
    mkdir -p "$SCAN_DIR/$SERVICE_ENUM_DIR" &> /dev/null
    mkdir -p "$SCAN_DIR/$VULN_DIR" &> /dev/null

    SELECT_WORDLISTS "$SCAN_DIR"

    echo -e "\n${BOLD_GREEN}Performing ping scan to find live hosts...${NC}"
    LOCAL_IPS=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -vE '^(127|169\.254)\.' | tr '\n' '|' | sed 's/|$//')

    nmap -sn "$TARGET" -oG - 2>/dev/null | grep -i "Status: Up" | awk '{print $2}' | \
        grep -Ev '(\.1$|\.254$)' | grep -Ev "$LOCAL_IPS" > "$SCAN_DIR/$HOST_SCAN_DIR/live_hosts.txt"

    LIVE_HOST_FILE="$SCAN_DIR/$HOST_SCAN_DIR/live_hosts.txt"
    if [[ ! -s "$LIVE_HOST_FILE" ]]; then
        echo -e "${BOLD_RED}No live hosts found. Exiting scan.${NC}"
        exit 1
    fi

    LIVE_HOST_COUNT=$(wc -l < "$LIVE_HOST_FILE")
    echo -e "${BOLD_GREEN}Found $LIVE_HOST_COUNT live hosts${NC}"

    echo -e "${BOLD_GREEN}Running full Nmap scan with NSE (this can take time)...${NC}"
    # Produce both human-readable and XML for searchsploit
    nmap -sS -sV -p- --script "default,vuln,auth" --max-retries 1 --host-timeout 600s -iL "$LIVE_HOST_FILE" -oN "$SCAN_DIR/$HOST_SCAN_DIR/nmap_full_scan.txt" -oX "$SCAN_DIR/$HOST_SCAN_DIR/nmap_full_scan.xml" &
    SPINNER_LOADER $!
    wait $!
    echo -e "${BOLD_GREEN}Full Nmap scan completed${NC}"

    # Run vulnerability mapping via searchsploit if available
    if command -v searchsploit &> /dev/null; then
        echo -e "${BOLD_GREEN}Running searchsploit against nmap XML results...${NC}"
        searchsploit --nmap "$SCAN_DIR/$HOST_SCAN_DIR/nmap_full_scan.xml" > "$SCAN_DIR/$VULN_DIR/searchsploit_results.txt" 2>/dev/null || true
        echo -e "${BOLD_GREEN}Searchsploit results saved: $SCAN_DIR/$VULN_DIR/searchsploit_results.txt${NC}"
    else
        echo -e "${BOLD_YELLOW}searchsploit not installed — skipping automated exploit search.${NC}"
    fi

    # Optional: run nikto for web servers found
    if command -v nikto &> /dev/null; then
        echo -e "${BOLD_GREEN}Scanning web services with nikto where found...${NC}"
        # find hosts with http services from nmap output
        grep -P "http" "$SCAN_DIR/$HOST_SCAN_DIR/nmap_full_scan.txt" | awk '{print $1}' | sort -u | while read -r host; do
            # nikto wants host/IP or URL; run simple host scan
            nikto -host "$host" -output "$SCAN_DIR/$VULN_DIR/nikto_${host}.txt" &> /dev/null &
            SPINNER_LOADER $!
            wait $!
        done
        echo -e "${BOLD_GREEN}Nikto scans (if any) completed.${NC}"
    else
        echo -e "${BOLD_YELLOW}nikto not installed — skipping web vulnerability scans.${NC}"
    fi

    # Weak credential checks (same as basic)
    echo -e "\n${BOLD_GREEN}Starting credential enumeration (SSH, FTP, Telnet, RDP)...${NC}"
    echo -e "${BOLD_GREEN}Using wordlists:${NC}"
    echo "  Usernames: $USERLIST ($(wc -l < "$USERLIST" 2>/dev/null || echo "0") entries)"
    echo "  Passwords: $PASSLIST ($(wc -l < "$PASSLIST" 2>/dev/null || echo "0") entries)"

    while read -r HOST; do
        HOST_DIR="$SCAN_DIR/$SERVICE_ENUM_DIR/$HOST"
        mkdir -p "$HOST_DIR"
        echo -e "\n${BOLD_GREEN}Processing host: $HOST${NC}"

        # Reuse checks from BASIC_SCAN (SSH, FTP, Telnet, RDP)
        if CHECK_SERVICE "$HOST" 22; then
            echo -e "${BOLD_GREEN}  SSH detected - starting brute-force...${NC}"
            RUN_HYDRA "ssh://$HOST" "ssh://$HOST" "$HOST_DIR/hydra_ssh_raw.txt"
            {
                echo "=== SSH Brute-Force Results for $HOST ==="
                echo "Date: $(date)"
                echo ""
                if grep -q "\[22\]\[ssh\] host:" "$HOST_DIR/hydra_ssh_raw.txt" 2>/dev/null; then
                    grep "\[22\]\[ssh\] host:" "$HOST_DIR/hydra_ssh_raw.txt" | sed 's/^/  /'
                else
                    echo "No successful SSH logins found."
                fi
                echo ""
                echo "Raw Hydra Output:"
                cat "$HOST_DIR/hydra_ssh_raw.txt" 2>/dev/null || true
            } > "$HOST_DIR/hydra_ssh.txt"
            rm -f "$HOST_DIR/hydra_ssh_raw.txt"
        fi

        if CHECK_SERVICE "$HOST" 21; then
            echo -e "${BOLD_GREEN}  FTP detected - starting brute-force...${NC}"
            RUN_HYDRA "ftp://$HOST" "ftp://$HOST" "$HOST_DIR/hydra_ftp_raw.txt"
            {
                echo "=== FTP Brute-Force Results for $HOST ==="
                echo "Date: $(date)"
                echo ""
                if grep -q "\[21\]\[ftp\] host:" "$HOST_DIR/hydra_ftp_raw.txt" 2>/dev/null; then
                    grep "\[21\]\[ftp\] host:" "$HOST_DIR/hydra_ftp_raw.txt" | sed 's/^/  /'
                else
                    echo "No successful FTP logins found."
                fi
                echo ""
                echo "Raw Hydra Output:"
                cat "$HOST_DIR/hydra_ftp_raw.txt" 2>/dev/null || true
            } > "$HOST_DIR/hydra_ftp.txt"
            rm -f "$HOST_DIR/hydra_ftp_raw.txt"
        fi

        if CHECK_SERVICE "$HOST" 23; then
            echo -e "${BOLD_GREEN}  Telnet detected - starting brute-force...${NC}"
            RUN_HYDRA "telnet://$HOST" "telnet://$HOST" "$HOST_DIR/hydra_telnet_raw.txt"
            {
                echo "=== TELNET Brute-Force Results for $HOST ==="
                echo "Date: $(date)"
                echo ""
                if grep -q "\[23\]\[telnet\] host:" "$HOST_DIR/hydra_telnet_raw.txt" 2>/dev/null; then
                    grep "\[23\]\[telnet\] host:" "$HOST_DIR/hydra_telnet_raw.txt" | sed 's/^/  /'
                else
                    echo "No successful TELNET logins found."
                fi
                echo ""
                echo "Raw Hydra Output:"
                cat "$HOST_DIR/hydra_telnet_raw.txt" 2>/dev/null || true
            } > "$HOST_DIR/hydra_telnet.txt"
            rm -f "$HOST_DIR/hydra_telnet_raw.txt"
        fi

        if CHECK_SERVICE "$HOST" 3389; then
            echo -e "${BOLD_GREEN}  RDP detected - starting brute-force...${NC}"
            RUN_HYDRA "rdp://$HOST" "rdp://$HOST" "$HOST_DIR/hydra_rdp_raw.txt"
            {
                echo "=== RDP Brute-Force Results for $HOST ==="
                echo "Date: $(date)"
                echo ""
                if grep -q "\[3389\]\[rdp\] host:" "$HOST_DIR/hydra_rdp_raw.txt" 2>/dev/null; then
                    grep "\[3389\]\[rdp\] host:" "$HOST_DIR/hydra_rdp_raw.txt" | sed 's/^/  /'
                else
                    echo "No successful RDP logins found."
                fi
                echo ""
                echo "Raw Hydra Output:"
                cat "$HOST_DIR/hydra_rdp_raw.txt" 2>/dev/null || true
            } > "$HOST_DIR/hydra_rdp.txt"
            rm -f "$HOST_DIR/hydra_rdp_raw.txt"
        fi

    done < "$LIVE_HOST_FILE"

    echo -e "\n${BOLD_GREEN}Full scan completed. Results saved in:${NC} $SCAN_DIR"
    echo -e "${BOLD_GREEN}Check these directories:${NC}"
    echo "  - Host discovery: $SCAN_DIR/$HOST_SCAN_DIR/"
    echo "  - Service enumeration: $SCAN_DIR/$SERVICE_ENUM_DIR/"
    echo "  - Vulnerability mapping: $SCAN_DIR/$VULN_DIR/"

    GENERATE_REPORT "$SCAN_DIR" # ADDED REPORT GENERATION
    POST_SCAN_MENU "$SCAN_DIR"
}
# =====================================

# ====== Generate Final Report (Markdown) ======
function GENERATE_REPORT() {
    local SCAN_DIR="$1"
    local REPORT_FILE="$SCAN_DIR/Consolidated_Report.md"
    local SCAN_TYPE
    
    if [[ "$SCAN_DIR" == *"full_scan"* ]]; then
        SCAN_TYPE="Full Scan (NSE + Vulnerability Mapping)"
    else
        SCAN_TYPE="Basic Scan (Port/Service + Weak Credentials)"
    fi

    echo -e "${BOLD_GREEN}Generating consolidated Markdown report...${NC}"

    {
        echo "# Network Security Scan Report"
        echo ""
        echo "## General Information"
        echo "- **Scan Type:** $SCAN_TYPE"
        echo "- **Target Range:** $TARGET"
        echo "- **Date:** $(date)"
        echo "- **Output Directory:** $(basename "$SCAN_DIR")"
        echo ""
        echo "## 1. Host Discovery"
        echo "### Live Hosts Found:"
        if [[ -f "$SCAN_DIR/$HOST_SCAN_DIR/live_hosts.txt" ]]; then
            echo "\`\`\`"
            cat "$SCAN_DIR/$HOST_SCAN_DIR/live_hosts.txt"
            echo "\`\`\`"
        else
            echo "No live hosts found or file missing."
        fi

        echo ""
        echo "## 2. Weak Credentials Found"
        echo "### Successful Logins (via Hydra):"
        echo "\`\`\`"
        # Search for successful logins in the service enumeration directory
        if grep -R -E "\[[0-9]{1,5}\]\[(ssh|ftp|telnet|rdp)\] host:" "$SCAN_DIR/$SERVICE_ENUM_DIR" 2>/dev/null; then
            grep -R -E "\[[0-9]{1,5}\]\[(ssh|ftp|telnet|rdp)\] host:" "$SCAN_DIR/$SERVICE_ENUM_DIR" | \
            sed -E 's/.*:([0-9]{1,3}\.){3}[0-9]{1,3}/  - /; s/ - \[/\n    [/' | \
            awk '!/Hydra finished/'
        else
            echo "No successful logins found."
        fi
        echo "\`\`\`"

        echo ""
        echo "## 3. Top Open Ports/Services"
        echo "### Sample from Nmap Full Scan:"
        echo "\`\`\`"
        # Extracts host, port, state, and service info from Nmap XML for clean display
        if [[ -f "$SCAN_DIR/$HOST_SCAN_DIR/nmap_full_scan.xml" ]]; then
            grep -E 'addr|portid' "$SCAN_DIR/$HOST_SCAN_DIR/nmap_full_scan.xml" | \
            sed 's/.*addr="\(.*\)" addrtype="ipv4".*/\nHost: \1/; s/.*portid="\([0-9]*\).*state service.*name="\([^"]*\).*/Port \1: \2/' | \
            grep -E 'Host:|Port' | head -n 20
        elif [[ -f "$SCAN_DIR/$HOST_SCAN_DIR/nmap_tcp_scan.txt" ]]; then
             grep -E 'open|filtered' "$SCAN_DIR/$HOST_SCAN_DIR/nmap_tcp_scan.txt" | head -n 20
        else
             echo "No detailed Nmap data to display."
        fi
        echo "\`\`\`"
        
        if [[ "$SCAN_TYPE" == *"Full Scan"* ]]; then
            echo ""
            echo "## 4. Vulnerability Mapping (Full Scan Only)"
            echo "### Top 5 Searchsploit Matches:"
            echo "\`\`\`"
            if [[ -f "$SCAN_DIR/$VULN_DIR/searchsploit_results.txt" ]]; then
                head -n 50 "$SCAN_DIR/$VULN_DIR/searchsploit_results.txt" | grep -A 2 -E "Exploit|Edb-ID" | head -n 50
            else
                echo "No Searchsploit data found."
            fi
            echo "\`\`\`"

            echo ""
            echo "### Nikto Web Scan Findings (Partial):"
            echo "\`\`\`"
            # Summarize Nikto reports
            find "$SCAN_DIR/$VULN_DIR" -type f -name 'nikto_*.txt' -print0 2>/dev/null | while IFS= read -r -d $'\0' file; do
                echo "File: $(basename "$file")"
                grep -E 'Vulnerability|ERROR|Server' "$file" | head -n 5
                echo "..."
            done
            echo "\`\`\`"
        fi

        echo ""
        echo "---"
        echo "Report saved to $REPORT_FILE"
        
    } > "$REPORT_FILE"

    echo -e "${BOLD_GREEN}Report saved successfully to: $REPORT_FILE${NC}"
}
# =====================================

# ====== Post-scan menu: search, save, zip ======
function POST_SCAN_MENU() {
    local SCAN_DIR="$1"
    while true; do
        echo -e "\n${BOLD_GREEN}Post-scan actions:${NC}"
        echo "1) Show brief summary of interesting findings"
        echo "2) Search inside results"
        echo "3) Save (zip) all results"
        echo "4) Open results folder (print path)"
        echo "5) Exit to main menu"
        echo -ne "${BOLD_GREEN}Enter choice [1-5]: ${NC}"
        read PS_CHOICE

        case $PS_CHOICE in
            1)
                SHOW_SUMMARY "$SCAN_DIR"
                ;;
            2)
                SEARCH_RESULTS "$SCAN_DIR"
                ;;
            3)
                ZIP_RESULTS "$SCAN_DIR"
                ;;
            4)
                echo -e "${BOLD_GREEN}Results folder: $SCAN_DIR${NC}"
                ;;
            5)
                break
                ;;
            *)
                echo -e "${BOLD_RED}Invalid option${NC}"
                ;;
        esac
    done
}
# =====================================

# ====== Show summary function ======
function SHOW_SUMMARY() {
    local SCAN_DIR="$1"
    echo -e "\n${BOLD_GREEN}Summary of findings in $SCAN_DIR:${NC}"

    echo -e "\n${BOLD_YELLOW}-- Live hosts --${NC}"
    if [[ -f "$SCAN_DIR/$HOST_SCAN_DIR/live_hosts.txt" ]]; then
        cat "$SCAN_DIR/$HOST_SCAN_DIR/live_hosts.txt"
    else
        echo "No live hosts file found."
    fi

    echo -e "\n${BOLD_YELLOW}-- Open services (sample from nmap outputs) --${NC}"
    grep -E "open|filtered" -R --line-number "$SCAN_DIR/$HOST_SCAN_DIR" "$SCAN_DIR/$HOST_SCAN_DIR" 2>/dev/null | head -n 20 || true
    grep -E "open|filtered" -R --line-number "$SCAN_DIR/$SERVICE_ENUM_DIR" "$SCAN_DIR" 2>/dev/null | head -n 20 || true

    echo -e "\n${BOLD_YELLOW}-- Weak credentials found (if any) --${NC}"
    grep -R "login:" -n "$SCAN_DIR" 2>/dev/null | head -n 20 || true
    # also check hydra outputs
    grep -R "\[22\]\[ssh\]|ftp\] host:|telnet\] host:" -n "$SCAN_DIR" 2>/dev/null | head -n 20 || true

    echo -e "\n${BOLD_YELLOW}-- Searchsploit results (if any) --${NC}"
    if [[ -d "$SCAN_DIR/$VULN_DIR" ]]; then
        head -n 40 "$SCAN_DIR/$VULN_DIR/searchsploit_results.txt" 2>/dev/null || echo "No searchsploit results or file not present."
    else
        echo "No vulnerability mapping directory present."
    fi

    echo -e "\n${BOLD_GREEN}End of summary.${NC}"
}
# =====================================

# ====== Search inside results ======
function SEARCH_RESULTS() {
    local SCAN_DIR="$1"
    echo -ne "${BOLD_GREEN}Enter search term / regex to look for in results: ${NC}"
    read SEARCH_TERM
    echo -e "${BOLD_GREEN}Searching...${NC}"
    grep -R -n --color=always -E "$SEARCH_TERM" "$SCAN_DIR" 2>/dev/null | less -R
}
# =====================================

# ====== Zip results ======
function ZIP_RESULTS() {
    local SCAN_DIR="$1"
    local ZIP_NAME
    ZIP_NAME="$(basename "$SCAN_DIR")"
    ZIP_NAME="${ZIP_NAME}.zip"
    echo -e "${BOLD_GREEN}Creating zip archive: $ZIP_NAME${NC}"
    (cd "$(dirname "$SCAN_DIR")" && zip -r "$ZIP_NAME" "$(basename "$SCAN_DIR")" > /dev/null) && echo -e "${BOLD_GREEN}Saved: $(pwd)/$(basename "$SCAN_DIR")/$ZIP_NAME (in parent directory)${NC}" || echo -e "${BOLD_RED}Zip failed${NC}"
}
# =====================================

# ====== Scan Type Menu ======
function SCAN_TYPE_MENU() {
    echo -e "\n${BOLD_GREEN}Select scan type:${NC}"
    echo "1) Basic Scan"
    echo "2) Full Scan (NSE + Vulnerbility mapping + Weak credentials)"
    echo "3) Exit"
    echo -ne "${BOLD_GREEN}Enter choice [1-3]: ${NC}"
    read SCAN_CHOICE

    case $SCAN_CHOICE in
        1)
            echo -e "${BOLD_GREEN}Running Basic Scan on $TARGET...${NC}"
            CHECK_TOOLS basic
            BASIC_SCAN
            ;;
        2)
            echo -e "${BOLD_GREEN}Running Full Scan on $TARGET...${NC}"
            CHECK_TOOLS full
            FULL_SCAN
            ;;
        3)
            echo -e "${BOLD_GREEN}Exiting.${NC}"
            exit 0
            ;;
        *)
            echo -e "${BOLD_RED}Invalid option, Try again.${NC}"
            SCAN_TYPE_MENU
            ;;
    esac
}
# =====================================

# ====== Main Menu Functionality ======
function MAIN_MENU() {
    echo -ne "${BOLD_GREEN}Network range to scan: ${NC}"
    read TARGET

    if [[ $TARGET =~ $CIDR_PATTERN || $TARGET =~ $WILDCARD_PATTERN || $TARGET =~ $RANGE_PATTERN || $TARGET =~ $FULL_RANGE_PATTERN ]]; then
        while true; do
            echo -ne "${BOLD_GREEN}Choose path for the output files (must exist): ${NC}"
            read -e MAIN_DIR

            MAIN_DIR="${MAIN_DIR/#\~/$HOME}"

            if [[ "$MAIN_DIR" != /* ]]; then
                MAIN_DIR="$(pwd)/$MAIN_DIR"
            fi

            if [[ -d "$MAIN_DIR" ]]; then
                echo -e "${BOLD_GREEN}Directory exists: $MAIN_DIR${NC}"
                break
            else
                echo -e "${BOLD_RED}Directory does not exist. Please create it first and try again.${NC}"
            fi
        done
        SCAN_TYPE_MENU
    else
        echo -e "\n${BOLD_RED}Invalid range, Try one of these formats:${NC}"
        echo " - 192.168.1.0/24"
        echo " - 192.168.1.*"
        echo " - 192.168.1.100-200"
        echo -e " - 192.168.1.1-192.168.1.254\n"
        MAIN_MENU
    fi
}

# ====== Start Script ======
echo -e "${BOLD_GREEN}=== Network Security Scanner ===${NC}"
echo -e "${BOLD_GREEN}Author: S22${NC}"
echo -e "${BOLD_RED}WARNING: Use only on networks you own or have explicit permission to test${NC}\n"

MAIN_MENU
