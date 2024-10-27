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
			header: `Hash=hash;Cert="-----BEGIN%20CERTIFICATE-----%0cert%0A-----END%20CERTIFICATE-----%0A";Subject="CN=hello,OU=hello,O=Acme\, Inc.";DNS=hello.west.example.com;DNS=hello.east.example.com,By=spiffe://mesh.example.com/ns/hellons/sa/hellosa;Hash=again;Subject="";URI=spiffe://mesh.example.com/ns/otherns/sa/othersa;URI=spiffe://mesh.example.com/ns/otherns/sa2/othersa2`,
			certs: []*ClientCert{
				{
					Hash: "hash",
					Cert: `-----BEGIN%20CERTIFICATE-----%0cert%0A-----END%20CERTIFICATE-----%0A`,
					Subject: &pkix.Name{
						CommonName:         "hello",
						OrganizationalUnit: []string{"hello"},
						Organization:       []string{"Acme, Inc."},
					},
					SubjectRaw: `CN=hello,OU=hello,O=Acme\, Inc.`,
					DNS: []string{"hello.west.example.com", "hello.east.example.com"},
				},
				{
					Hash: "again",
					By:   "spiffe://mesh.example.com/ns/hellons/sa/hellosa",
					URI:  []string{"spiffe://mesh.example.com/ns/otherns/sa/othersa", "spiffe://mesh.example.com/ns/otherns/sa2/othersa2"},
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

func TestParseSubject(t *testing.T) {
	testCases := []struct {
		subject string
		name    *pkix.Name
		err     bool
	}{
		{
			subject: "",
			name:    nil,
			err:     false,
		},
		{
			subject: "C=US,O=Test Inc,CN=test.com",
			name: &pkix.Name{
				Country:      []string{"US"},
				Organization: []string{"Test Inc"},
				CommonName:   "test.com",
			},
			err: false,
		},

		{subject: `C`, err: true},
		{subject: `C=`, err: true},
		{subject: `unknown=hello`, err: true},
		{subject: `CN="random"`, err: true},
		{subject: `CN="random=hello"`, err: true},
	}

	for _, tc := range testCases {
		t.Run(tc.subject, func(t *testing.T) {
			name, err := ParseSubject(tc.subject)
			if tc.err {
				assert.Error(t, err)
				assert.Empty(t, name)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.name, name)
			}
		})
	}
}
