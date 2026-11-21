package report

// BannerLines is the enki half-block wordmark.
var BannerLines = []string{
	"▄▄▄▄▄▄ ▄▄  ▄▄ ▄▄ ▄▄ ▄▄",
	"█▀▀▀▀  ██▄▄██ ██▄██ ██",
	"█████  ██  ██ ██ ██ ██",
	"█▄▄▄▄  ██  ██ ██ ██ ██",
}

const (
	// Brand is the product name shown with the tagline.
	Brand = "ENKI"
	// Tagline is the product descriptor.
	Tagline = "AI Security Posture"
	// Title is the full branded line used in the UI and CLI headers.
	Title = Brand + " - " + Tagline
)
