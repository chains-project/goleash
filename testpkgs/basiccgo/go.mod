module basiccgo

go 1.23.2

require "example.com" v0.0.0
replace (
	"example.com" v0.0.0 => "../example.com"
)