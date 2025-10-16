package migrations

import "embed"

// FS contains all migration files embedded at build time
//
//go:embed files/*.sql
var FS embed.FS
