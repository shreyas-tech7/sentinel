// Practice sample: private-key literal embedded in source.
func signToken() string {
    privateKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC0exampleNOTAKEY0practice0filler0material0here0ab
-----END RSA PRIVATE KEY-----`)
    return jwt.SignHS256(claims, privateKey)
}
