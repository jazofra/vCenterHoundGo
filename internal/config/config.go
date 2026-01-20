package config

// Config holds the runtime configuration
type Config struct {
	Host        string
	User        string
	Password    string
	Port        int
	OutputPath  string
	Debug       bool
	BHURL       string
	BHKeyID     string
	BHKeySecret string
	// Computer sync configuration
	TargetDomains     []string          // Static list of domains for computer sync (e.g., ["VMS.AD.VARIAN.COM"])
	SyncComputers     bool              // Enable computer sync
	SyncComputersAPI  bool              // Use BloodHound API to fetch computers (slower but more accurate)
}
