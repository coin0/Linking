package conf

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
	ServiceIPv6 *string
	RelayedIPv6 *string
	RelayedInf6 *string
	Port     *string
	Cert     *string
	Key      *string
	Realm    *string
	Users    arrayflags
	Http     *string
	Log      *string
	LogSize  *string
	LogNum   *string
	CpuProf  *string
	MemProf  *string
}

type clientArgs struct {

	ServerIP   string
	ServerPort int
	Proto      string
	Username   *string
	Password   *string
	Debug      *bool
	Log        *string
	LogSize    *string
	LogNum     *string
	SelfTest   *string
	VerifyCert *bool
}

var (
	Args       argument
	ClientArgs clientArgs
)
