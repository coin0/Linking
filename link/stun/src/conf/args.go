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
	ServiceIP *string
	RelayedIP *string
	Port     *string
	SecPort  *string
	Cert     *string
	Key      *string
	Realm    *string
	Users    arrayflags
	Http     *string
	Log      *string
}

type clientArgs struct {

	ServerIP   string
	ServerPort int
	Proto      string
	Username   *string
	Password   *string
	Debug      *bool
}

var (
	Args       argument
	ClientArgs clientArgs
)
