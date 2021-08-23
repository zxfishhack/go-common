package jwt

const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`