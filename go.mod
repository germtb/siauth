module siauth

go 1.23.4

require google.golang.org/protobuf v1.36.8

require github.com/germtb/sidb v0.0.0

require (
	github.com/mattn/go-sqlite3 v1.14.32 // indirect
	golang.org/x/crypto v0.41.0 // indirect
)

replace github.com/germtb/sidb => ../sidb
