package xfccparser

import (
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseXFCCHeader(t *testing.T) {
	testCases := []struct {
		header string
		certs  []*ClientCert
		err    bool
	}{
		{
			header: ``,
			certs:  nil,
		},
		{
			header: `Hash=hash;Cert="-----BEGIN%20CERTIFICATE-----%0cert%0A-----END%20CERTIFICATE-----%0A";Subject="CN=hello,OU=hello,O=Acme\, Inc.";URI=;DNS=hello.west.example.com;DNS=hello.east.example.com,By=spiffe://mesh.example.com/ns/hellons/sa/hellosa;Hash=again;Subject="";URI=spiffe://mesh.example.com/ns/otherns/sa/othersa`,
			certs: []*ClientCert{
				{
					Hash: "hash",
					Cert: `-----BEGIN%20CERTIFICATE-----%0cert%0A-----END%20CERTIFICATE-----%0A`,
					Subject: pkix.Name{
						CommonName:         "hello",
						OrganizationalUnit: []string{"hello"},
						Organization:       []string{"Acme, Inc."},
					},
					DNS: []string{"hello.west.example.com", "hello.east.example.com"},
				},
				{
					Hash: "again",
					By:   "spiffe://mesh.example.com/ns/hellons/sa/hellosa",
					URI:  "spiffe://mesh.example.com/ns/otherns/sa/othersa",
				},
			},
		},

		{header: `Hash`, err: true},
		{header: `Hash=;Hash`, err: true},
		{header: `unknown=hello`, err: true},
		{header: `Subject="random"`, err: true},
		{header: `Subject="random=hello"`, err: true},
	}

	for _, tc := range testCases {
		// nolint: scopelint
		t.Run(tc.header, func(t *testing.T) {
			certs, err := ParseXFCCHeader(tc.header)
			if tc.err {
				assert.Error(t, err)
				assert.Empty(t, certs)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.certs, certs)
			}
		})
	}
}
