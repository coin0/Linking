package conf

import (
	"util/cred"
	"time"
)

const (
	USER_CHECK_INT         = 10  // seconds

	// delete user account if expiry exceeds max retention value (seconds)
	// 0 means account should be removed immediately when expired
	USER_EXP_MAX_RETENTION = 0   // seconds
)

var (
	Users     *cred.AccountBook
)

func init() {

	// create a default account book for server
	Users = cred.NewAccountBook()

	go func() {
		ticker := time.NewTicker(time.Second * USER_CHECK_INT)
		for {
			select {
			case <-ticker.C:
				// clean up expired user accounts
				Users.Cleanup(time.Second * USER_EXP_MAX_RETENTION)
			}
		}
	}()
}
