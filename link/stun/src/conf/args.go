package conf

import (
	"crypto/tls"
)

// -------------------------------------------------------------------------------------------------

type arrayflags []string

func (this *arrayflags) String() string {

	return ""
}

func (this *arrayflags) Set(value string) error {

	*this = append(*this, value)

	return nil
}

// -------------------------------------------------------------------------------------------------

type argument struct {

	ServiceIP   *string
	RelayedIP   *string
	RelayedInf  *string
	RestfulIP   *string
	OtherIP     *string
	OtherPort   *int
	OtherPort2  *int
	OtherHttp   *int
	ServiceIPv6 *string
	RelayedIPv6 *string
	RelayedInf6 *string
	Port     *int
	Port2    *int
	Cert     *string
	Key      *string
	CertKeys arrayflags
	Certs    []tls.Certificate
	Realm    *string
	Users    arrayflags
	Http     *int
	Log      *string
	LogSize  *int
	LogNum   *int
	CpuProf  *string
	MemProf  *string
	IPFilter *bool
}

type clientArgs struct {

	ServerIP   string
	ServerPort int
	ClientIP   string
	ClientPort int
	Proto      string
	Username   *string
	Password   *string
	Debug      *bool
	Log        *string
	LogSize    *int
	LogNum     *int
	SelfTest   *uint
	VerifyCert *bool
}

var (
	Args       argument
	ClientArgs clientArgs
)
