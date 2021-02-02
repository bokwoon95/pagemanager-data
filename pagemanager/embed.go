// +build embed

package pagemanager

import "embed"

//go:embed *.css *.js
var files embed.FS

func init() {
   pagemanagerFS = files
}
