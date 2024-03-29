package ntlm

// anonymousKeyExchangeKey is the key-exchange-key used when there is no user/pass, i.e. anonymous login.
// It is defined in MS-NLMP. The key-exchange-key is used to protect the random session key generated by the client
// during the NTLM authentication process. In the case of authenticated login with user/pass, the key-exchange-key
// is generated off of the hash of part of the authentication message that includes the user credentials. In the
// case of anonymous login, the key-exchange-key is a constant value of all zeros.
// See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c50a85f0-5940-42d8-9e82-ed206902e919
var anonymousKeyExchangeKey = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
