package security

import (
	"fmt"
	"os"
)

// AppArmorProfile defines the security profile configuration
type AppArmorProfile struct {
	Name          string // Profile name used in SecurityOpt (e.g., "nodejs-restricted")
	InstalledPath string // Path in /etc/apparmor.d/
	LocalPath     string // Path in apparmor_custom_profiles/ (for installation)
}

// GetAppArmorProfileForEnv returns the appropriate AppArmor profile for the environment type
func GetAppArmorProfileForEnv(envType string) AppArmorProfile {
	switch envType {
	case "node":
		return AppArmorProfile{
			Name:          "nodejs-restricted",
			InstalledPath: "/etc/apparmor.d/nodejs-restricted",
			LocalPath:     "apparmor_custom_profiles/nodejs-restricted",
		}
	case "python":
		return AppArmorProfile{
			Name:          "docker-default",
			InstalledPath: "",
			LocalPath:     "",
		}
	case "go":
		return AppArmorProfile{
			Name:          "docker-default",
			InstalledPath: "",
			LocalPath:     "",
		}
	default:
		return AppArmorProfile{
			Name:          "docker-default",
			InstalledPath: "",
			LocalPath:     "",
		}
	}
}

// VerifyAppArmorProfileExists checks if the custom AppArmor profile is installed
// Checks /etc/apparmor.d/ first (production install), then local folder (development)
func verifyAppArmorProfileExists(profile AppArmorProfile) (bool, string, error) {
	// Return true for default profiles
	if profile.InstalledPath == "" {
		return true, profile.Name, nil
	}

	// Check if profile is installed in /etc/apparmor.d/
	info, err := os.Stat(profile.InstalledPath)
	if err == nil && !info.IsDir() {
		// Profile found in /etc/apparmor.d/
		return true, profile.Name, nil
	}

	// If not found in /etc/apparmor.d/, check the local path
	if profile.LocalPath != "" {
		info, err = os.Stat(profile.LocalPath)
		if err == nil && !info.IsDir() {
			// Profile exists locally but not installed
			return false, profile.Name, fmt.Errorf("profile exists locally but not installed in %s", profile.InstalledPath)
		}
	}

	// Profile not found anywhere
	return false, profile.Name, fmt.Errorf("AppArmor profile '%s' not found at %s or %s", profile.Name, profile.InstalledPath, profile.LocalPath)
}

// EnsureAppArmorProfileLoaded checks if the AppArmor profile is available and loaded
// Must be called BEFORE creating the Docker container
// Returns the profile name to use in Docker SecurityOpt
func EnsureAppArmorProfileLoaded(profile AppArmorProfile) (string, error) {
	// Default profiles don't need verification
	if profile.InstalledPath == "" {
		return profile.Name, nil
	}

	installed, profileName, err := verifyAppArmorProfileExists(profile)
	if !installed {
		// Profile not installed, provide instructions
		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
		fmt.Printf("\nTo install the profile, run:\n")
		fmt.Printf("  sudo ./setup_apparmor.sh\n")
		fmt.Printf("\nOr manually:\n")
		fmt.Printf("  sudo cp %s %s\n", profile.LocalPath, profile.InstalledPath)
		fmt.Printf("  sudo chmod 644 %s\n", profile.InstalledPath)
		fmt.Printf("  sudo apparmor_parser -r %s\n", profile.InstalledPath)
		fmt.Printf("  sudo systemctl reload apparmor\n")
		return "", err
	}

	fmt.Printf("AppArmor profile '%s' is ready at %s\n", profileName, profile.InstalledPath)
	return profileName, nil
}
