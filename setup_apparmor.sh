#!/bin/bash

# AppArmor Profile Installation Script
# This script loads the custom AppArmor profiles for Dependency Guard

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROFILE_DIR="$SCRIPT_DIR/apparmor_custom_profiles"

echo "AppArmor Profile Installer for Dependency Guard"
echo "================================================"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root (use sudo)"
   exit 1
fi

# Check if AppArmor is installed
if ! command -v apparmor_parser &> /dev/null; then
    echo "Error: apparmor-parser not found. Please install AppArmor:"
    echo "  Ubuntu/Debian: sudo apt-get install apparmor apparmor-utils"
    echo "  Fedora: sudo dnf install apparmor apparmor-utils"
    exit 1
fi

# Check if profiles directory exists
if [[ ! -d "$PROFILE_DIR" ]]; then
    echo "Error: Profile directory not found at $PROFILE_DIR"
    exit 1
fi

echo "Found profiles directory: $PROFILE_DIR"
echo ""

# Install and load all profile files (excluding README.md)
echo "Installing profiles to /etc/apparmor.d/..."
echo ""

for profile_file in "$PROFILE_DIR"/*; do
    if [[ -f "$profile_file" && ! "$profile_file" =~ \.md$ ]]; then
        profile_name=$(basename "$profile_file")
        destination="/etc/apparmor.d/$profile_name"
        
        echo "Installing: $profile_name"
        
        # Copy the profile to /etc/apparmor.d/
        if cp "$profile_file" "$destination"; then
            echo "  ✓ Copied to $destination"
        else
            echo "  ✗ Failed to copy $profile_name to /etc/apparmor.d/"
            exit 1
        fi
        
        # Set correct permissions
        chmod 644 "$destination"
        
        # Load the profile
        if apparmor_parser -r "$destination"; then
            echo "  ✓ Successfully loaded $profile_name"
        else
            echo "  ✗ Failed to load $profile_name"
            exit 1
        fi
        
        echo ""
    fi
done

echo ""
echo "Reloading AppArmor service..."
if systemctl is-active --quiet apparmor; then
    systemctl reload apparmor
    echo "  ✓ AppArmor service reloaded"
else
    echo "  ⚠ AppArmor service is not running, but profiles are loaded"
fi

echo ""
echo "✓ All AppArmor profiles installed successfully!"
echo ""
echo "To verify the loaded profiles, run:"
echo "  sudo aa-status"
