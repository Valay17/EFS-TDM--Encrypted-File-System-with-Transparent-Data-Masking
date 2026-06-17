#!/usr/bin/env bash
# Open 6 isolated terminal sessions, one per role.
#
# Each terminal gets:
#   - Its own HOME (/tmp/efs_<role>) so session files never collide
#   - Its own downloads dir (/tmp/efs_<role>/downloads/)
#   - Working directory set to portable_client/
#   - A config.json pointing at the server (copied from libs/)
#   - A greeting showing the role and credentials to use
#
# All you need to do in each terminal is: ./EFS web-login
#
# Credentials match the sample DB seeded by scripts/generate_samples.py.
# If you seeded the DB with different passwords, update the list below.
#
# Cleanup:
#   rm -rf /tmp/efs_admin /tmp/efs_analyst /tmp/efs_contributor \
#           /tmp/efs_viewer /tmp/efs_auditor /tmp/efs_guest

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE="$(dirname "$SCRIPT_DIR")/portable_client"
BINARY="$BASE/EFS"

if [ ! -x "$BINARY" ]; then
    echo "Error: $BINARY not found. Run scripts/build_client.sh first."
    exit 1
fi

# Detect terminal emulator
TERM_EMU=""
for t in qterminal xfce4-terminal gnome-terminal konsole xterm; do
    if command -v "$t" &>/dev/null; then
        TERM_EMU="$t"
        break
    fi
done

if [ -z "$TERM_EMU" ]; then
    echo "No supported terminal emulator found."
    echo "Install one of: qterminal xfce4-terminal gnome-terminal konsole xterm"
    exit 1
fi

# Get screen dimensions (pixels); fall back to 1920x1080
read -r SCR_W SCR_H < <(
    if command -v xdpyinfo &>/dev/null; then
        xdpyinfo | awk '/dimensions:/ { split($2, a, "x"); print a[1], a[2] }'
    else
        echo "1920 1080"
    fi
)

# Grid cell size (3 columns x 2 rows)
CELL_W=$(( SCR_W / 3 ))
CELL_H=$(( SCR_H / 2 ))

# Index counter incremented per session (0-5)
SESSION_IDX=0

# Calculate pixel position for a grid cell (3 cols x 2 rows)
calc_pos() {
    local idx=$1
    local col=$(( idx % 3 ))
    local row=$(( idx / 3 ))
    echo $(( col * CELL_W )) $(( row * CELL_H ))
}

# Roles: "role_key:DisplayName:password"
SESSIONS=(
    "admin:Admin:Admin1234!"
    "analyst:Analyst:Analyst1234!"
    "contributor:Contributor:Contrib1234!"
    "viewer:Viewer:Viewer1234!"
    "auditor:Auditor:Auditor1234!"
    "guest:Guest:Guest1234!"
)

open_session() {
    local key="$1"
    local name="$2"
    local pass="$3"
    local home_dir="/tmp/efs_${key}"
    local pos_x pos_y
    read -r pos_x pos_y < <(calc_pos "$SESSION_IDX")
    SESSION_IDX=$(( SESSION_IDX + 1 ))

    # Set up isolated home
    mkdir -p "$home_dir"

    # Copy config.json from libs/ so the binary knows the server address
    if [ -f "$BASE/libs/config.json" ]; then
        mkdir -p "$home_dir"
        cp "$BASE/libs/config.json" "$home_dir/.efs_config_ref.json"
    fi

    # Build the shell init script that runs inside the terminal
    local init_script="/tmp/efs_init_${key}.sh"
    cat > "$init_script" << INIT
#!/bin/sh
export HOME="$home_dir"
export EFS_ROLE_HINT="$name"
cd "$BASE"
clear
echo "================================================"
echo "  EFS-TDM session: $name"
echo "  Home:            $home_dir"
echo "  Downloads:       $home_dir/downloads/"
echo "================================================"
echo ""
echo "  Username : ${key}"
echo "  Password : ${pass}"
echo ""
echo "  Run:  ./EFS web-login"
echo "        ./EFS shell          (if already logged in)"
echo ""
exec bash --norc --noprofile
INIT
    chmod +x "$init_script"

    # Launch terminal
    case "$TERM_EMU" in
        qterminal)
            qterminal --title "EFS: $name" -e "$init_script" &
            ;;
        xfce4-terminal)
            xfce4-terminal --title="EFS: $name" -x "$init_script" &
            ;;
        gnome-terminal)
            gnome-terminal --title="EFS: $name" -- "$init_script" &
            ;;
        konsole)
            konsole --title "EFS: $name" -e "$init_script" &
            ;;
        xterm)
            xterm -title "EFS: $name" -e "$init_script" &
            ;;
    esac

    # Wait for the window to appear then move and resize it into the grid cell
    local win_title="EFS: $name"
    ( xdotool search --sync --name "$win_title" \
        windowsize "$CELL_W" "$CELL_H" \
        windowmove "$pos_x" "$pos_y" ) &

    sleep 0.2
}

echo "Starting 6 EFS sessions from: $BASE"
echo "Terminal emulator: $TERM_EMU"
echo ""

for entry in "${SESSIONS[@]}"; do
    IFS=: read -r key name pass <<< "$entry"
    echo "  Opening: $name  ($key)"
    open_session "$key" "$name" "$pass"
done

echo ""
echo "All 6 terminals launched."
echo "To clean up session files:"
echo "  rm -rf /tmp/efs_admin /tmp/efs_analyst /tmp/efs_contributor /tmp/efs_viewer /tmp/efs_auditor /tmp/efs_guest /tmp/efs_init_*.sh"
