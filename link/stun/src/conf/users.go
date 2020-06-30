package conf

import (
	"util/cred"
)

var (
	Users     *cred.AccountBook
)

func init() {

	Users = cred.NewAccountBook()
}
