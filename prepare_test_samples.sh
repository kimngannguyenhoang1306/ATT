#!/bin/bash
# prepare_test_samples.sh
# Script để chọn 10 malware, 10 benign từ decoded folder
# rồi truy ngược lại raw_apk để lấy APK gốc rồi move đi

set -e

# Configuration
DECODED_MALWARE="decoded/malware"
DECODED_BENIGN="decoded/benign"
RAW_MALWARE="raw_apk/malware"
RAW_BENIGN="raw_apk/benign"

TEST_DIR="test_samples"
MALWARE_TEST_DIR="$TEST_DIR/malware_decoded"
BENIGN_TEST_DIR="$TEST_DIR/benign_decoded"
MALWARE_APK_DIR="$TEST_DIR/malware_apks"
BENIGN_APK_DIR="$TEST_DIR/benign_apks"
RESULT_DIR="$TEST_DIR/results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}MOSDroid Test Sample Preparation${NC}"
echo -e "${BLUE}(Select 10 from decoded, trace back to raw APK)${NC}"
echo -e "${BLUE}================================================${NC}"

# Create test directory structure
echo -e "${YELLOW}[*] Creating test directories...${NC}"
mkdir -p "$MALWARE_TEST_DIR"
mkdir -p "$BENIGN_TEST_DIR"
mkdir -p "$MALWARE_APK_DIR"
mkdir -p "$BENIGN_APK_DIR"
mkdir -p "$RESULT_DIR"

# Function to find corresponding APK file
# Example: decoded folder name is "app123" -> look for "app123.apk" or the hash name
find_corresponding_apk() {
    local app_name=$1
    local apk_source_dir=$2
    
    # Try exact match first: app_name.apk
    if [ -f "$apk_source_dir/$app_name.apk" ]; then
        echo "$apk_source_dir/$app_name.apk"
        return 0
    fi
    
    # Try matching by name substring
    local apk_file=$(find "$apk_source_dir" -maxdepth 1 -name "*$app_name*" -type f 2>/dev/null | head -1)
    if [ -n "$apk_file" ]; then
        echo "$apk_file"
        return 0
    fi
    
    return 1
}

# Function to copy decoded APK and corresponding original APK
copy_sample() {
    local decoded_folder=$1
    local app_name=$(basename "$decoded_folder")
    local label=$2
    local target_decoded_dir=$3
    local target_apk_dir=$4
    local source_apk_dir=$5
    
    # Check if decoded folder has smali
    if [ ! -d "$decoded_folder/smali" ]; then
        echo -e "${RED}✗${NC} No smali in: $app_name (skip)"
        return 1
    fi
    
    # Copy decoded APK
    cp -r "$decoded_folder" "$target_decoded_dir/" 2>/dev/null || {
        echo -e "${RED}✗${NC} Failed to copy decoded: $app_name"
        return 1
    }
    echo -e "${GREEN}✓${NC} Copied decoded: $app_name"
    
    # Find and copy corresponding original APK
    local apk_file=$(find_corresponding_apk "$app_name" "$source_apk_dir")
    if [ -f "$apk_file" ]; then
        cp "$apk_file" "$target_apk_dir/" 2>/dev/null
        echo -e "${GREEN}  └─ APK: $(basename "$apk_file")${NC}"
    else
        echo -e "${YELLOW}  ⚠ APK not found for: $app_name${NC}"
    fi
    
    return 0
}

# Process malware
echo -e "\n${YELLOW}[*] Processing malware samples...${NC}"
if [ ! -d "$DECODED_MALWARE" ]; then
    echo -e "${RED}✗ $DECODED_MALWARE not found!${NC}"
    malware_count=0
else
    malware_count=0
    for decoded_folder in $(find "$DECODED_MALWARE" -maxdepth 1 -type d ! -name "$DECODED_MALWARE" | sort | head -10); do
        if [ $malware_count -ge 10 ]; then
            break
        fi
        
        if copy_sample "$decoded_folder" "malware" "$MALWARE_TEST_DIR" "$MALWARE_APK_DIR" "$RAW_MALWARE"; then
            ((malware_count++))
        fi
    done
fi

# Process benign
echo -e "\n${YELLOW}[*] Processing benign samples...${NC}"
if [ ! -d "$DECODED_BENIGN" ]; then
    echo -e "${RED}✗ $DECODED_BENIGN not found!${NC}"
    benign_count=0
else
    benign_count=0
    for decoded_folder in $(find "$DECODED_BENIGN" -maxdepth 1 -type d ! -name "$DECODED_BENIGN" | sort | head -10); do
        if [ $benign_count -ge 10 ]; then
            break
        fi
        
        if copy_sample "$decoded_folder" "benign" "$BENIGN_TEST_DIR" "$BENIGN_APK_DIR" "$RAW_BENIGN"; then
            ((benign_count++))
        fi
    done
fi

# Summary
echo -e "\n${BLUE}================================================${NC}"
echo -e "${BLUE}Summary${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "Malware samples copied: ${GREEN}$malware_count/10${NC}"
echo -e "Benign samples copied:  ${GREEN}$benign_count/10${NC}"
echo -e ""
echo -e "Structure created:"
echo -e "  ${GREEN}$MALWARE_TEST_DIR${NC}     (decoded malware)"
echo -e "  ${GREEN}$BENIGN_TEST_DIR${NC}       (decoded benign)"
echo -e "  ${GREEN}$MALWARE_APK_DIR${NC}    (original malware APKs)"
echo -e "  ${GREEN}$BENIGN_APK_DIR${NC}     (original benign APKs)"
echo -e "  ${GREEN}$RESULT_DIR${NC}        (test results)"

echo -e "\n${YELLOW}[*] Ready for testing!${NC}"
echo -e "${YELLOW}[*] Run: python step5_batch.py${NC}"
echo -e "${BLUE}================================================${NC}"
