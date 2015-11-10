package rand

import (
	"io"
)

/*
Reader is a global, cryptographically strong pseudo-random generator.
*/
var Reader io.Reader
