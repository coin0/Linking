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
	IP       *string
	Port     *string
	Realm    *string
	Users    arrayflags
	Http     *string
}

type clientArgs struct {

	ServerIP   *string
	ServerPort *int
	PeerIP     *string
	PeerPort   *int
	Username   *string
	Password   *string
}

var (
	Args       argument
	ClientArgs clientArgs
)
