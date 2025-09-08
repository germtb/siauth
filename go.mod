module siauth

go 1.23.4

require google.golang.org/protobuf v1.36.8

require github.com/germtb/sidb v0.0.0

require (
	github.com/mattn/go-sqlite3 v1.14.32 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/grpc v1.75.0 // indirect
)

replace github.com/germtb/sidb => ../sidb
