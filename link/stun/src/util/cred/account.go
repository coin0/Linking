package cred

import (
	"sync"
	"time"
	"fmt"
	"util/dbg"
	"crypto/md5"
	"crypto/sha256"
	. "util/log"
)

const (
	ACCOUNT_DEFAULT_EXPIRY       = 300 // seconds
)

type account struct {

	enabled      bool
	createdAt    time.Time

	// password string
	password       string
	passwordSHA256 string

	// account expiry
	expiry       bool
	validBefore  time.Time

	// RFC8489 security feature
	// https://www.rfc-editor.org/rfc/rfc8489#section-18.1
	secFeatEnabled bool
}

type AccountBook struct {

	accounts    map[string]*account
	accountLck  *sync.RWMutex
}

// -------------------------------------------------------------------------------------------------

func genMD5Key(user, realm, psw string) string {

	key := md5.Sum([]byte(user + ":" + realm + ":" + psw))
	return string(key[0:16])
}

func genSHA256Key(user, realm, psw string) string {

	h := sha256.New()
	h.Write([]byte(user + ":" + realm + ":" + psw))
	key := h.Sum(nil)
	return string(key[0:32])
}

// -------------------------------------------------------------------------------------------------

func NewAccountBook() *AccountBook {

	return &AccountBook{
		accounts:   map[string]*account{},
		accountLck: &sync.RWMutex{},
	}
}

func (book *AccountBook) Add(name, realm, psw string) error {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	if _, ok := book.accounts[name]; ok {
		return fmt.Errorf("user already exists")
	}

	book.accounts[name] = &account{
		enabled:     true,
		createdAt:   time.Now(),
		password:    genMD5Key(name, realm, psw),
		expiry:      true,
		validBefore: time.Now().Add(time.Duration(ACCOUNT_DEFAULT_EXPIRY) * time.Second),
		secFeatEnabled: true,
		passwordSHA256: genSHA256Key(name, realm, psw),
	}
	Info("cred: create account '%s'", name)

	return nil
}

func (book *AccountBook) Delete(name string) {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	delete(book.accounts, name)
}

func (book *AccountBook) Find(name string) (string, error) {

	book.accountLck.RLock()
	defer book.accountLck.RUnlock()

	if acc, err := book.check(name); err != nil {
		return "", err
	} else {
		return acc.password, nil
	}
}

func (book *AccountBook) FindSHA256(name string) (string, error) {

	book.accountLck.RLock()
	defer book.accountLck.RUnlock()

	if acc, err := book.check(name); err != nil {
		return "", err
	} else {
		return acc.passwordSHA256, nil
	}
}

func (book *AccountBook) Has(name string) bool {

	book.accountLck.RLock()
	defer book.accountLck.RUnlock()

	_, ok := book.accounts[name]
	return ok
}

func (book *AccountBook) Refresh(name string, expiry time.Time) error {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	acc, ok := book.accounts[name]
	if !ok {
		return fmt.Errorf("not found")
	}

	// set expiry
	acc.validBefore = expiry

	return nil
}

func (book *AccountBook) Reset(name, realm, psw string) error {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	acc, ok := book.accounts[name]
	if !ok {
		return fmt.Errorf("not found")
	}

	// set password
	acc.password = genMD5Key(name, realm, psw)
	acc.passwordSHA256 = genSHA256Key(name, realm, psw)

	return nil
}

func (book *AccountBook) Enable(name string) error {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	acc, ok := book.accounts[name]
	if !ok {
		return fmt.Errorf("not found")
	}

	acc.enabled = true

	return nil
}

func (book *AccountBook) Disable(name string) error {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	acc, ok := book.accounts[name]
	if !ok {
		return fmt.Errorf("not found")
	}

	acc.enabled = false

	return nil
}

func (book *AccountBook) ExpiryOn(name string) error {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	acc, ok := book.accounts[name]
	if !ok {
		return fmt.Errorf("not found")
	}

	acc.expiry = true

	return nil
}

func (book *AccountBook) ExpiryOff(name string) error {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	acc, ok := book.accounts[name]
	if !ok {
		return fmt.Errorf("not found")
	}

	acc.expiry = false

	return nil
}

func (book *AccountBook) IsSecFeatEnabled(name string) (bool, error) {

	book.accountLck.RLock()
	defer book.accountLck.RUnlock()

	acc, ok := book.accounts[name]
	if !ok {
		return false, fmt.Errorf("not found")
	}

	return acc.secFeatEnabled, nil
}

func (book *AccountBook) Cleanup(dur time.Duration) int {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	// delete expired credentials according to the given duration since expiry
	now := time.Now()
	n := 0
	for name, acc := range book.accounts {
		if acc.expiry && now.Sub(acc.validBefore).Nanoseconds() > dur.Nanoseconds() {
			Info("cred: delete account '%s'", name)
			delete(book.accounts, name)
			n++
		}
	}

	return n
}

func (book *AccountBook) check(name string) (*account, error) {

	// check name
	acc, ok := book.accounts[name]
	if !ok {
		return nil, fmt.Errorf("not found")
	}

	// check enabled
	if !acc.enabled {
		return nil, fmt.Errorf("account not valid")
	}

	// check expiry
	if acc.expiry && time.Now().After(acc.validBefore) {
		return nil, fmt.Errorf("account expired")
	}

	return acc, nil
}

func (book *AccountBook) UserTable() (result string) {

	book.accountLck.RLock()
	defer book.accountLck.RUnlock()

	for name, acc := range book.accounts {
		enabled := ""
		if !acc.enabled {
			enabled = "[inactive]"
		}
		result += fmt.Sprintf("user=%s %s\n", name, enabled)
		result += fmt.Sprintf("  MD5=%s\n", dbg.DumpMem([]byte(acc.password), 0))
		result += fmt.Sprintf("  SHA256=%s\n", dbg.DumpMem([]byte(acc.passwordSHA256), 0))
		result += fmt.Sprintf("  createdAt=%s\n", acc.createdAt.Format("2006-01-02 15:04:05"))

		expiry := ""
		if acc.expiry {
			expiry = acc.validBefore.Format("2006-01-02 15:04:05")
		}
		if len(expiry) > 0 {
			expired := ""
			if time.Now().After(acc.validBefore) {
				expired = "[expired]"
			}
			result += fmt.Sprintf("  expiry=%s %s\n", expiry, expired)
		}

		result += fmt.Sprintf("  securityFeature=%v\n", acc.secFeatEnabled)
	}

	return
}
