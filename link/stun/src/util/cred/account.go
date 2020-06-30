package cred

import (
	"sync"
	"time"
	"fmt"
)

const (
	ACCOUNT_DEFAULT_EXPIRY       = 365 // days
)

type account struct {

	enabled      bool
	createdAt    time.Time

	// password string
	password     string

	// account expiry
	expiry       bool
	validBefore  time.Time
}

type AccountBook struct {

	accounts    map[string]*account
	accountLck  *sync.Mutex
}

func NewAccountBook() *AccountBook {

	return &AccountBook{
		accounts:   map[string]*account{},
		accountLck: &sync.Mutex{},
	}
}

func (book *AccountBook) Add(name, psw string) error {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	if _, ok := book.accounts[name]; ok {
		return fmt.Errorf("user already exists")
	}

	book.accounts[name] = &account{
		enabled:     true,
		createdAt:   time.Now(),
		password:    psw,
		expiry:      true,
		validBefore: time.Now().Add(time.Duration(ACCOUNT_DEFAULT_EXPIRY) * time.Hour * 24),
	}

	return nil
}

func (book *AccountBook) Delete(name string) {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	delete(book.accounts, name)
}

func (book *AccountBook) Find(name string) (string, error) {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	if psw, err := book.check(name); err != nil {
		return "", err
	} else {
		return psw, nil
	}
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

func (book *AccountBook) Reset(name, psw string) error {

	book.accountLck.Lock()
	defer book.accountLck.Unlock()

	acc, ok := book.accounts[name]
	if !ok {
		return fmt.Errorf("not found")
	}

	// set password
	acc.password = psw

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

func (book *AccountBook) check(name string) (string, error) {

	// check name
	acc, ok := book.accounts[name]
	if !ok {
		return "", fmt.Errorf("not found")
	}

	// check enabled
	if !acc.enabled {
		return "", fmt.Errorf("account not valid")
	}

	// check expiry
	if time.Now().After(acc.validBefore) {
		return "", fmt.Errorf("account expired")
	}

	return acc.password, nil
}
