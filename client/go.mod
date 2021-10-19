module cert-manager/client

go 1.16

require (
	cert-manager/common v0.0.0-00010101000000-000000000000
	google.golang.org/protobuf v1.27.1
)

replace cert-manager/common => ../common
