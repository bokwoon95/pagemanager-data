// +build embed

package pagemanager2

import "embed"

//go:embed *.css *.js
var files embed.FS

func init() {
   pagemanagerFS = files
}
