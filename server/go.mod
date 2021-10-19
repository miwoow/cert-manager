module cert-manager/server

go 1.16

require (
	cert-manager/common v0.0.0-00010101000000-000000000000
	gopkg.in/yaml.v2 v2.4.0
)

replace cert-manager/common => ../common
