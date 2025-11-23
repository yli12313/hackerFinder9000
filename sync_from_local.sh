#!/bin/bash
# Sync script to pull classifier/threat modeling code from local machine
# Run this FROM YOUR LOCAL MACHINE (arthurcolle@chrysalis)
#
# Usage: ./sync_from_local.sh <remote_host>
# Example: ./sync_from_local.sh ubuntu@your-server-ip

set -e

REMOTE_HOST="${1:-ubuntu@your-server-ip}"
REMOTE_PATH="/home/ubuntu/hackerFinder9000"
LOCAL_PATH="/Users/arthurcolle/apart-defense/Apart-Hackathon-Hackerbot9K"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Sync Script: Local -> Remote ===${NC}"
echo "Local:  $LOCAL_PATH"
echo "Remote: $REMOTE_HOST:$REMOTE_PATH"
echo ""

# Check if local path exists
if [ ! -d "$LOCAL_PATH" ]; then
    echo -e "${RED}Error: Local path does not exist: $LOCAL_PATH${NC}"
    exit 1
fi

# Test SSH connection
echo -e "${YELLOW}Testing SSH connection...${NC}"
if ! ssh -o ConnectTimeout=5 "$REMOTE_HOST" "echo 'Connection OK'" 2>/dev/null; then
    echo -e "${RED}Error: Cannot connect to $REMOTE_HOST${NC}"
    exit 1
fi
echo -e "${GREEN}SSH connection successful${NC}"
echo ""

# Create backup directory on remote
BACKUP_DIR="$REMOTE_PATH/.backup_$(date +%Y%m%d_%H%M%S)"
echo -e "${YELLOW}Creating backup directory on remote: $BACKUP_DIR${NC}"
ssh "$REMOTE_HOST" "mkdir -p $BACKUP_DIR"

# Backup conflicting files on remote (files that exist on both sides)
echo -e "${YELLOW}Backing up potentially conflicting files...${NC}"
ssh "$REMOTE_HOST" "
    cd $REMOTE_PATH
    # Backup files that might be overwritten
    [ -f src/main.py ] && cp src/main.py $BACKUP_DIR/main.py.bak
    [ -f src/detection/__init__.py ] && cp src/detection/__init__.py $BACKUP_DIR/detection_init.py.bak
    echo 'Backup complete'
"

echo ""
echo -e "${YELLOW}=== Syncing NEW files (won't overwrite existing) ===${NC}"

# Sync new detection modules (these don't exist on remote)
echo "Syncing new detection modules..."
rsync -avz --progress \
    "$LOCAL_PATH/src/detection/chain_detector.py" \
    "$LOCAL_PATH/src/detection/online_learner.py" \
    "$LOCAL_PATH/src/detection/rnn_weight_modulator.py" \
    "$LOCAL_PATH/src/detection/threat_detector.py" \
    "$REMOTE_HOST:$REMOTE_PATH/src/detection/"

# Sync detection models directory (new on remote)
echo ""
echo "Syncing detection models..."
rsync -avz --progress \
    "$LOCAL_PATH/src/detection/models/" \
    "$REMOTE_HOST:$REMOTE_PATH/src/detection/models/"

# Sync content_analyzer.py (new on remote)
echo ""
echo "Syncing content_analyzer.py..."
rsync -avz --progress \
    "$LOCAL_PATH/src/content_analyzer.py" \
    "$REMOTE_HOST:$REMOTE_PATH/src/"

# Sync training scripts (new on remote)
echo ""
echo "Syncing training scripts..."
rsync -avz --progress \
    "$LOCAL_PATH/src/train_full_spectrum.py" \
    "$LOCAL_PATH/src/train_with_params.py" \
    "$REMOTE_HOST:$REMOTE_PATH/src/"

echo ""
echo -e "${YELLOW}=== Files that need MANUAL MERGE ===${NC}"
echo -e "${RED}The following files exist on both sides and may have different content:${NC}"
echo "  - src/main.py"
echo "  - src/detection/__init__.py"
echo ""
echo "Backups saved to: $BACKUP_DIR"
echo ""

# Show diff preview for conflicting files
echo -e "${YELLOW}Would you like to see diffs for conflicting files? (y/n)${NC}"
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    echo ""
    echo -e "${YELLOW}=== Diff: src/detection/__init__.py ===${NC}"
    ssh "$REMOTE_HOST" "cat $REMOTE_PATH/src/detection/__init__.py" > /tmp/remote_init.py 2>/dev/null || true
    diff -u /tmp/remote_init.py "$LOCAL_PATH/src/detection/__init__.py" || true

    echo ""
    echo -e "${YELLOW}=== Diff: src/main.py (first 100 lines) ===${NC}"
    ssh "$REMOTE_HOST" "head -100 $REMOTE_PATH/src/main.py" > /tmp/remote_main.py 2>/dev/null || true
    diff -u /tmp/remote_main.py <(head -100 "$LOCAL_PATH/src/main.py") || true
fi

echo ""
echo -e "${YELLOW}=== Options for conflicting files ===${NC}"
echo "1) Keep remote versions (no action needed)"
echo "2) Overwrite with local versions (use --force flag)"
echo "3) Manually merge the files"
echo ""
echo -e "${GREEN}Sync of NEW files complete!${NC}"
echo ""
echo "To force overwrite conflicting files, run:"
echo "  $0 $REMOTE_HOST --force"
