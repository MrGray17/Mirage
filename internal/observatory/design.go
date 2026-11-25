package observatory

import _ "embed"

//go:embed design.css
var designCSS string

// DesignCSS returns the shared static presentation stylesheet.
func DesignCSS() string { return designCSS }
