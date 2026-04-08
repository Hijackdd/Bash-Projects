#!/bin/bash

# ================================================================
# Memory Forensics Analysis Script
# ================================================================
# Student Name: Matan Ohayon
# Student Code: s22  
# Class Code: TMagen773637
# Lecturer Name: Erel Regev
# 
# Description: Automated HDD and Memory Analysis Tool
# Tools Used: Bulk Extractor, Binwalk, Foremost, Strings, Volatility
# 
# Credits and References:
# - ChatGPT / Gemini
# - Lecturer Erel Regev
# - Classmates
# ================================================================

MAIN_FOLDER="Memory_Dump_Result"
TOOLS_LIST="bulk_extractor binwalk foremost strings volatility"
FILE_PATH=""
MEMORY_PROFILE=""

function CREATE_TOOL_FOLDERS() {
    TOOL_NAME=$1
    case $TOOL_NAME in
        all)
            mkdir -p "$MAIN_FOLDER/Volatility/Volatility Results"
            mkdir -p "$MAIN_FOLDER/Bulk Extractor/Bulk Extractor Results"
            mkdir -p "$MAIN_FOLDER/Binwalk/Binwalk Results"
            mkdir -p "$MAIN_FOLDER/Foremost/Foremost Results"
            mkdir -p "$MAIN_FOLDER/Strings/Strings Results"
            mkdir -p "$MAIN_FOLDER/Human_Readable/Human Readable Results"
            ;;
        volatility) mkdir -p "$MAIN_FOLDER/Volatility/Volatility Results" ;;
        bulk_extractor) mkdir -p "$MAIN_FOLDER/Bulk Extractor/Bulk Extractor Results" ;;
        binwalk) mkdir -p "$MAIN_FOLDER/Binwalk/Binwalk Results" ;;
        foremost) mkdir -p "$MAIN_FOLDER/Foremost/Foremost Results" ;;
        strings) mkdir -p "$MAIN_FOLDER/Strings/Strings Results" ;;
        human_readable) mkdir -p "$MAIN_FOLDER/Human_Readable/Human Readable Results" ;;
    esac
}

function CHECK_TOOLS() {
    TOOL_TO_CHECK=$1
    if [[ "$TOOL_TO_CHECK" == "all" ]]; then
        echo -e "\n\e[32m[*]\e[0m Checking if forensics tools are installed...\n"
        for SINGLE_TOOL in $TOOLS_LIST; do
            INSTALL_TOOL_IF_NEEDED "$SINGLE_TOOL"
        done
        echo
    else
        echo -e "\n\e[32m[*]\e[0m Checking if $TOOL_TO_CHECK is installed...\n"
        INSTALL_TOOL_IF_NEEDED "$TOOL_TO_CHECK"
        echo
    fi
}

function INSTALL_TOOL_IF_NEEDED() {
    TOOL_NAME=$1
    echo -ne "    ➤ Checking $TOOL_NAME... "
    which $TOOL_NAME &> /dev/null
    if [ "$?" == "0" ]; then
        echo -e "\e[32mInstalled\e[0m"
    else
        echo -e "\e[31mNot installed\e[0m - Installing..."
        if [ "$TOOL_NAME" == "bulk_extractor" ]; then
            sudo apt install bulk-extractor -y &> /dev/null
        elif [ "$TOOL_NAME" == "strings" ]; then
            sudo apt install binutils -y &> /dev/null
        elif [ "$TOOL_NAME" == "volatility" ]; then
            which git &> /dev/null || sudo apt install git -y &> /dev/null
            git clone https://github.com/volatilityfoundation/volatility.git "$MAIN_FOLDER/Volatility/Volatility Tool" &> /dev/null
        else
            sudo apt install "$TOOL_NAME" -y &> /dev/null
        fi
        echo -e "    ➤ \e[32m$TOOL_NAME installed.\e[0m"
    fi
}

function SETUP_VOLATILITY_DEPS() {
    echo -e "\n\e[34m[~]\e[0m Setting up Volatility dependencies..."
    sudo apt update &> /dev/null
    sudo apt install -y python2 python2-dev build-essential &> /dev/null
    if ! command -v pip2 &> /dev/null; then
        curl -s https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
        sudo python2 get-pip.py &> /dev/null
        rm -f get-pip.py
    fi
    python2 -c "import distorm3" 2>/dev/null || {
        sudo apt install -y python-distorm3 &> /dev/null
        python2 -c "import distorm3" 2>/dev/null || sudo pip2 install distorm3 &> /dev/null
    }
    python2 -c "from Crypto.Hash import MD5" 2>/dev/null || sudo pip2 install pycrypto &> /dev/null
    echo -e "\e[32m    ➤ Dependencies setup completed.\e[0m"
}

function CHECK_NETWORK_FILE() {
    echo -ne "\n\e[34m[~]\e[0m Checking for network traffic file: packets.pcap...\n"
    BULKEX_PATH="$MAIN_FOLDER/Bulk Extractor/Bulk Extractor Results"
    NET_FILE=$(find "$BULKEX_PATH" -type f -name "packets.pcap" | head -n 1)
    if [[ -f "$NET_FILE" ]]; then
        FILE_SIZE=$(stat -c%s "$NET_FILE" 2>/dev/null || echo "0")
        SIZE_MB=$((FILE_SIZE / 1024 / 1024))
        echo -e "\e[32m[*]\e[0m Network traffic file found:"
        echo -e "    ➤ Path: $NET_FILE"
        echo -e "    ➤ Size: ${FILE_SIZE} bytes (${SIZE_MB} MB)\n"
    else
        echo -e "\e[33m[!]\e[0m Network file 'packets.pcap' couldn't be found.\n"
    fi
}

function FIND_HUMAN_READABLE() {
    echo -e "\n\e[34m[~]\e[0m Searching for human-readable content (exe files, passwords, usernames)..."
    CREATE_TOOL_FOLDERS human_readable
    HUMAN_DIR="$MAIN_FOLDER/Human_Readable/Human Readable Results"
    
    # Search for common executable patterns
    strings "$FILE_PATH" | grep -i "\.exe\|\.dll\|\.sys" | head -100 > "$HUMAN_DIR/executable_files.txt" 2>/dev/null
    
    # Search for password patterns
    strings "$FILE_PATH" | grep -iE "(password|passwd|pwd|pass)[[:space:]]*[:=][[:space:]]*[a-zA-Z0-9]+" | head -50 > "$HUMAN_DIR/passwords.txt" 2>/dev/null
    
    # Search for username patterns  
    strings "$FILE_PATH" | grep -iE "(user|username|login|account)[[:space:]]*[:=][[:space:]]*[a-zA-Z0-9]+" | head -50 > "$HUMAN_DIR/usernames.txt" 2>/dev/null
    
    # Search for email addresses
    strings "$FILE_PATH" | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | head -50 > "$HUMAN_DIR/email_addresses.txt" 2>/dev/null
    
    # Search for URLs
    strings "$FILE_PATH" | grep -oE "https?://[a-zA-Z0-9./?=_%:-]*" | head -50 > "$HUMAN_DIR/urls.txt" 2>/dev/null
    
    echo -e "\e[32m    ➤ Human-readable content search completed.\e[0m"
}

function VOLATILITY() {
    SETUP_VOLATILITY_DEPS
    echo -e "\n\e[34m[~]\e[0m Starting Volatility analysis..."
    
    # Check if file can be analyzed by Volatility
    VALID_EX="raw dd bin img dmp vmem elf lime psmem mem"
    EXT=$(echo "$FILE_PATH" | awk -F '.' '{print $NF}')
    IS_VALID=false
    for EXT_OK in $VALID_EX; do
        if [[ "$EXT" == "$EXT_OK" ]]; then IS_VALID=true; break; fi
    done
    
    if [[ "$IS_VALID" == "true" ]]; then
        echo -e "\e[32m[*]\e[0m File can be analyzed with Volatility."
        
        # Find memory profile and save to variable
        echo -e "\e[34m[~]\e[0m Detecting memory profile..."
        MEMORY_PROFILE=$(python2 "$MAIN_FOLDER/Volatility/Volatility Tool/vol.py" -f "$FILE_PATH" imageinfo 2>/dev/null | grep "Suggested Profile" | head -1 | awk '{print $4}' | sed 's/,//')
        
        if [[ -z "$MEMORY_PROFILE" ]]; then
            MEMORY_PROFILE="Win7SP1x86"
            echo -e "\e[33m[!]\e[0m Could not detect profile, using default: $MEMORY_PROFILE"
        else
            echo -e "\e[32m[*]\e[0m Memory profile detected: $MEMORY_PROFILE"
        fi
        
        # Save memory profile to variable file for report
        echo "$MEMORY_PROFILE" > "$MAIN_FOLDER/Volatility/.memory_profile"
        
# Display running processes
echo -e "\e[34m[~]\e[0m Extracting running processes..."
python2 "$MAIN_FOLDER/Volatility/Volatility Tool/vol.py" -f "$FILE_PATH" --profile="$MEMORY_PROFILE" pslist > "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_pslist.txt" 2>/dev/null

# Display the content of the pslist file
cat "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_pslist.txt"

PROCESS_COUNT=$(grep -c "0x" "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_pslist.txt" 2>/dev/null || echo "0")
echo -e "\e[32m    ➤ Found $PROCESS_COUNT running processes.\e[0m"
        
# Display network connections
echo -e "\e[34m[~]\e[0m Extracting network connections..."
python2 "$MAIN_FOLDER/Volatility/Volatility Tool/vol.py" -f "$FILE_PATH" --profile="$MEMORY_PROFILE" netscan > "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_netscan.txt" 2>/dev/null

# Display the content of the netscan file
cat "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_netscan.txt"

NETWORK_COUNT=$(grep -c "TCP\|UDP" "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_netscan.txt" 2>/dev/null || echo "0")
echo -e "\e[32m    ➤ Found $NETWORK_COUNT network connections.\e[0m"
        
        # Attempt to extract registry information
        echo -e "\e[34m[~]\e[0m Attempting to extract registry information..."
        python2 "$MAIN_FOLDER/Volatility/Volatility Tool/vol.py" -f "$FILE_PATH" --profile="$MEMORY_PROFILE" hivelist > "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_hivelist.txt" 2>/dev/null
        HIVE_COUNT=$(grep -c "0x" "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_hivelist.txt" 2>/dev/null || echo "0")
        if [[ "$HIVE_COUNT" -gt "0" ]]; then
            echo -e "\e[32m    ➤ Found $HIVE_COUNT registry hives.\e[0m"
            
            # Try to extract some registry keys
            python2 "$MAIN_FOLDER/Volatility/Volatility Tool/vol.py" -f "$FILE_PATH" --profile="$MEMORY_PROFILE" printkey > "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_printkey.txt" 2>/dev/null
            python2 "$MAIN_FOLDER/Volatility/Volatility Tool/vol.py" -f "$FILE_PATH" --profile="$MEMORY_PROFILE" userassist > "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_userassist.txt" 2>/dev/null
        else
            echo -e "\e[33m[!]\e[0m No registry hives found or extraction failed.\e[0m"
        fi
        
        # Run other Volatility plugins
        VOL_PLUGINS="shellbags shimcache hashdump svcscan envars"
        for SINGLE_PLUGIN in $VOL_PLUGINS; do
            python2 "$MAIN_FOLDER/Volatility/Volatility Tool/vol.py" -f "$FILE_PATH" --profile="$MEMORY_PROFILE" "$SINGLE_PLUGIN" > "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_$SINGLE_PLUGIN.txt" 2>/dev/null
        done
        
        echo -e "\e[32m[*]\e[0m Volatility analysis completed.\e[0m"
    else
        echo -e "\e[31m[!]\e[0m File cannot be analyzed with Volatility (unsupported format).\e[0m"
    fi
}

function STRINGS() {
    echo -e "\n\e[34m[~]\e[0m Running strings analysis..."
    strings "$FILE_PATH" > "$MAIN_FOLDER/Strings/Strings Results/Strings Results.txt" 2>/dev/null
    echo -e "\e[32m[*]\e[0m Strings analysis completed.\e[0m"
}

function BULK_EXTRACTOR() {
    echo -e "\n\e[34m[~]\e[0m Running Bulk Extractor..."
    bulk_extractor "$FILE_PATH" -o "$MAIN_FOLDER/Bulk Extractor/Bulk Extractor Results" &> /dev/null
    echo -e "\e[32m[*]\e[0m Bulk Extractor completed.\e[0m"
    CHECK_NETWORK_FILE
}

function FOREMOST() {
    echo -e "\n\e[34m[~]\e[0m Running Foremost..."
    foremost "$FILE_PATH" -o "$MAIN_FOLDER/Foremost/Foremost Results" &> /dev/null
    echo -e "\e[32m[*]\e[0m Foremost completed.\e[0m"
}

function BINWALK() {
    echo -e "\n\e[34m[~]\e[0m Running Binwalk..."
    binwalk "$FILE_PATH" > "$MAIN_FOLDER/Binwalk/Binwalk Results/binwalk_output.txt"
    echo -e "\e[32m[*]\e[0m Binwalk completed.\e[0m"
}

function GENERATE_REPORT() {
    echo -e "\n\e[34m[~]\e[0m Generating final report..."
    REPORT_FILE="$MAIN_FOLDER/Analysis_Report.txt"
    
    # Header information
    echo "================================================================" > "$REPORT_FILE"
    echo "             MEMORY FORENSICS ANALYSIS REPORT" >> "$REPORT_FILE"
    echo "================================================================" >> "$REPORT_FILE"
    echo "File Analyzed: $FILE_PATH" >> "$REPORT_FILE"
    echo "Analysis Date: $(date)" >> "$REPORT_FILE"
    echo "Analyst: [Student Name Here]" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    
    # Memory profile information
    if [[ -f "$MAIN_FOLDER/Volatility/.memory_profile" ]]; then
        PROFILE_USED=$(cat "$MAIN_FOLDER/Volatility/.memory_profile")
        echo "Memory Profile Used: $PROFILE_USED" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    echo "GENERAL STATISTICS:" >> "$REPORT_FILE"
    echo "===================" >> "$REPORT_FILE"
    
    # File analysis statistics
    TOTAL_FILES=0
    
    # Bulk Extractor
    if [[ -d "$MAIN_FOLDER/Bulk Extractor/Bulk Extractor Results" ]]; then
        COUNT=$(find "$MAIN_FOLDER/Bulk Extractor/Bulk Extractor Results" -type f | wc -l)
        TOTAL_FILES=$((TOTAL_FILES + COUNT))
    else
        COUNT=0
    fi
    echo "Bulk Extractor Files Found: $COUNT" >> "$REPORT_FILE"

    # Foremost
    if [[ -d "$MAIN_FOLDER/Foremost/Foremost Results" ]]; then
        COUNT=$(find "$MAIN_FOLDER/Foremost/Foremost Results" -type f | wc -l)
        TOTAL_FILES=$((TOTAL_FILES + COUNT))
    else
        COUNT=0
    fi
    echo "Foremost Files Recovered: $COUNT" >> "$REPORT_FILE"

    # Binwalk
    BINWALK_FILE="$MAIN_FOLDER/Binwalk/Binwalk Results/binwalk_output.txt"
    if [[ -f "$BINWALK_FILE" ]]; then
        LINES=$(wc -l < "$BINWALK_FILE")
    else
        LINES=0
    fi
    echo "Binwalk Signatures Found: $LINES" >> "$REPORT_FILE"

    # Strings
    STRINGS_FILE="$MAIN_FOLDER/Strings/Strings Results/Strings Results.txt"
    if [[ -f "$STRINGS_FILE" ]]; then
        LINES=$(wc -l < "$STRINGS_FILE")
    else
        LINES=0
    fi
    echo "Strings Extracted: $LINES" >> "$REPORT_FILE"

    # Volatility results
    if [[ -d "$MAIN_FOLDER/Volatility/Volatility Results" ]]; then
        COUNT=$(find "$MAIN_FOLDER/Volatility/Volatility Results" -type f -name "*.txt" | wc -l)
        
        # Process count
        if [[ -f "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_pslist.txt" ]]; then
            PROC_COUNT=$(grep -c "0x" "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_pslist.txt" 2>/dev/null || echo "0")
            echo "Running Processes Found: $PROC_COUNT" >> "$REPORT_FILE"
        fi
        
        # Network connections
        if [[ -f "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_netscan.txt" ]]; then
            NET_COUNT=$(grep -c "TCP\|UDP" "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_netscan.txt" 2>/dev/null || echo "0")
            echo "Network Connections Found: $NET_COUNT" >> "$REPORT_FILE"
        fi
        
        # Registry hives
        if [[ -f "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_hivelist.txt" ]]; then
            HIVE_COUNT=$(grep -c "0x" "$MAIN_FOLDER/Volatility/Volatility Results/Volatility_hivelist.txt" 2>/dev/null || echo "0")
            echo "Registry Hives Found: $HIVE_COUNT" >> "$REPORT_FILE"
        fi
    else
        COUNT=0
    fi
    echo "Volatility Analysis Files: $COUNT" >> "$REPORT_FILE"

    # Human readable content
    if [[ -d "$MAIN_FOLDER/Human_Readable/Human Readable Results" ]]; then
        EXE_COUNT=$(wc -l < "$MAIN_FOLDER/Human_Readable/Human Readable Results/executable_files.txt" 2>/dev/null || echo "0")
        PASS_COUNT=$(wc -l < "$MAIN_FOLDER/Human_Readable/Human Readable Results/passwords.txt" 2>/dev/null || echo "0")
        USER_COUNT=$(wc -l < "$MAIN_FOLDER/Human_Readable/Human Readable Results/usernames.txt" 2>/dev/null || echo "0")
        EMAIL_COUNT=$(wc -l < "$MAIN_FOLDER/Human_Readable/Human Readable Results/email_addresses.txt" 2>/dev/null || echo "0")
        
        echo "Executable References Found: $EXE_COUNT" >> "$REPORT_FILE"
        echo "Password References Found: $PASS_COUNT" >> "$REPORT_FILE"
        echo "Username References Found: $USER_COUNT" >> "$REPORT_FILE"
        echo "Email Addresses Found: $EMAIL_COUNT" >> "$REPORT_FILE"
    fi

    echo "" >> "$REPORT_FILE"
    echo "TOTAL FILES RECOVERED: $TOTAL_FILES" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    # Time analysis
    if [[ -f "$MAIN_FOLDER/.start_time" ]]; then
        RAW=$(cat "$MAIN_FOLDER/.start_time")
        START_SEC=$(echo "$RAW" | cut -d'|' -f1)
        START_DATE=$(echo "$RAW" | cut -d'|' -f2-)
        END_SEC=$(date +%s)
        TOTAL_TIME=$((END_SEC - START_SEC))
        echo "TIMING INFORMATION:" >> "$REPORT_FILE"
        echo "===================" >> "$REPORT_FILE"
        echo "Analysis Start Time: $START_DATE" >> "$REPORT_FILE"
        echo "Analysis End Time: $(date)" >> "$REPORT_FILE"
        echo "Total Analysis Duration: ${TOTAL_TIME} seconds" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    echo "TOOLS USED:" >> "$REPORT_FILE"
    echo "===========" >> "$REPORT_FILE"
    echo "- Volatility Framework (Memory Analysis)" >> "$REPORT_FILE"
    echo "- Bulk Extractor (Data Carving)" >> "$REPORT_FILE"
    echo "- Foremost (File Recovery)" >> "$REPORT_FILE"
    echo "- Binwalk (Firmware Analysis)" >> "$REPORT_FILE"
    echo "- Strings (Text Extraction)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "Report generated by Memory Dump - Memory Forensics Toolkit" >> "$REPORT_FILE"
    echo "================================================================" >> "$REPORT_FILE"

    # Create final zip archive
    ZIP_NAME="Forensics_Report_$(date +%Y%m%d_%H%M%S).zip"
    zip -r "$ZIP_NAME" "$MAIN_FOLDER" &> /dev/null
    rm -rf "$MAIN_FOLDER"
    echo -e "\e[32m[*]\e[0m Report generated successfully!"
    echo -e "\e[32m[*]\e[0m Final analysis package: $ZIP_NAME"
}

function USER_MENU() {
    echo -e "\n\e[36m====================================================\e[0m"
    echo -e "\e[36m      MEMORY FORENSICS - USER TOOL MENU\e[0m"
    echo -e "\e[36m====================================================\e[0m"

    echo -e "\n\e[32m[*]\e[0m Please enter path to memory file to investigate:\n"
    read -e FILE_PATH

    if [ -f "$FILE_PATH" ]; then
        echo -e "\n\e[32m[*]\e[0m File found successfully!\n"
        echo -e "\e[32m[*]\e[0m What would you like to do?\n"
        echo -e "    1) Analyze memory with all tools"
        echo -e "    2) Choose a specific tool\n"

        read -p $'\n\e[31m[*]\e[0m Enter your choice: ' USER_CHOICE

        case $USER_CHOICE in
            1)
                date "+%s|%a %d %b %Y %H:%M:%S" > "$MAIN_FOLDER/.start_time"
                CHECK_TOOLS all
                CREATE_TOOL_FOLDERS all
                VOLATILITY
                BULK_EXTRACTOR
                FOREMOST
                BINWALK
                STRINGS
                FIND_HUMAN_READABLE
                GENERATE_REPORT
                ;;
            2)
                echo -e "\n\e[32m[*]\e[0m Choose a tool:\n"
                echo -e "    1) Volatility"
                echo -e "    2) Bulk Extractor"
                echo -e "    3) Foremost"
                echo -e "    4) Binwalk"
                echo -e "    5) Strings\n"

                read -p $'\n\e[31m[*]\e[0m Your choice: ' TOOL_CHOICE

                date "+%s|%a %d %b %Y %H:%M:%S" > "$MAIN_FOLDER/.start_time"

                case $TOOL_CHOICE in
                    1) CHECK_TOOLS volatility; CREATE_TOOL_FOLDERS volatility; VOLATILITY ;;
                    2) CHECK_TOOLS bulk_extractor; CREATE_TOOL_FOLDERS bulk_extractor; BULK_EXTRACTOR; FIND_HUMAN_READABLE ;;
                    3) CHECK_TOOLS foremost; CREATE_TOOL_FOLDERS foremost; FOREMOST ;;
                    4) CHECK_TOOLS binwalk; CREATE_TOOL_FOLDERS binwalk; BINWALK ;;
                    5) CHECK_TOOLS strings; CREATE_TOOL_FOLDERS strings; STRINGS; FIND_HUMAN_READABLE ;;
                    *) echo -e "\n\e[31m[!]\e[0m Invalid selection." ;;
                esac

                GENERATE_REPORT
                ;;
            *)
                echo -e "\n\e[31m[!]\e[0m Invalid menu selection."
                ;;
        esac
    else
        echo -e "\n\e[31m[!]\e[0m The file path doesn't exist. Please check and try again.\n"
    fi
}

function STARTUP() {
    if [ "$(whoami)" == "root" ]; then
        clear
        command -v figlet &> /dev/null && command -v lolcat &> /dev/null && figlet "Memory Dump" | lolcat || echo "Memory Dump - Memory Forensics Toolkit"
        echo -e "
\e[36m==============================================================\e[0m
 Welcome to \e[32mMemory Dump\e[0m - A Memory Forensics Toolkit for Linux

 This tool helps you analyze memory dumps using various open-source
 forensic tools. You can choose full or individual analysis methods.

 \e[33mRun as ROOT to make sure all tools work properly.\e[0m
\e[36m==============================================================\e[0m
"
        mkdir -p "$MAIN_FOLDER"
        USER_MENU
    else
        echo -e "\n\e[31m[!]\e[0m Please run this script as ROOT user. Exiting..."
        exit
    fi
}

STARTUP
