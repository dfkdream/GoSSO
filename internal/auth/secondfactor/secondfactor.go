package secondfactor

type SecondFactor interface {
	DisplayName() string
	Icon() string
	Endpoint() string
}
