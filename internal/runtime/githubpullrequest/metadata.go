// Package githubpullrequest defines M5.4's narrow, deterministic GitHub
// pull-request effect. Models and plans are data only; only the lifecycle may
// invoke the mutation client added by the later implementation phase.
package githubpullrequest

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/MrGray17/Mirage/internal/contracts"
)

const (
	MetadataVersion = contracts.PullRequestMetadataV1
	maxTitleBytes   = 120
	maxBodyBytes    = 4 << 10
)

var ErrInvalidMetadata = errors.New("invalid deterministic GitHub PR metadata")

type MetadataSpec struct {
	RunID                     string
	ContractHash              string
	Operation                 string
	Resource                  string
	CommitOID                 string
	PublicationRecordIdentity string
}

type Metadata struct {
	version        string
	identity       string
	title          string
	body           string
	titleDigest    string
	bodyDigest     string
	resourceDigest string
}

type canonicalMetadata struct {
	Version        string `json:"version"`
	Title          string `json:"title"`
	Body           string `json:"body"`
	TitleDigest    string `json:"title_digest"`
	BodyDigest     string `json:"body_digest"`
	ResourceDigest string `json:"resource_digest"`
}

func NewMetadata(spec MetadataSpec) (*Metadata, error) {
	if strings.TrimSpace(spec.RunID) == "" || spec.RunID != strings.TrimSpace(spec.RunID) || !utf8.ValidString(spec.RunID) || len(spec.RunID) > 256 || !validDigest(spec.ContractHash) || spec.Operation != "MODIFY" || strings.TrimSpace(spec.Resource) == "" || !utf8.ValidString(spec.Resource) || !strings.HasPrefix(spec.Resource, "/workspace/") || !validOID(spec.CommitOID) || !validDigest(spec.PublicationRecordIdentity) {
		return nil, fmt.Errorf("%w: trusted structured input is incomplete", ErrInvalidMetadata)
	}
	runDigest := sha256.Sum256([]byte(spec.RunID))
	title := "MIRAGE verified change " + hex.EncodeToString(runDigest[:])[:12]
	resourceBytes := []byte(spec.Resource)
	resourceEncoded := base64.RawURLEncoding.EncodeToString(resourceBytes)
	resourceDigest := bytesDigest(resourceBytes)
	body := strings.Join([]string{
		"MIRAGE verified change",
		"",
		"- run_identity: `" + bytesDigest([]byte(spec.RunID)) + "`",
		"- contract_identity: `" + spec.ContractHash + "`",
		"- mutation: `MODIFY`",
		"- resource_b64url: `" + resourceEncoded + "`",
		"- resource_sha256: `" + resourceDigest + "`",
		"- commit_oid: `" + spec.CommitOID + "`",
		"- publication_record: `" + spec.PublicationRecordIdentity + "`",
		"",
		"This change was shadow-executed and verified by MIRAGE.",
	}, "\n")
	if len(title) > maxTitleBytes || len(body) > maxBodyBytes || !safeGeneratedMetadata(title, false) || !safeGeneratedMetadata(body, true) {
		return nil, fmt.Errorf("%w: generated title or body violates bounds", ErrInvalidMetadata)
	}
	canonical := canonicalMetadata{Version: MetadataVersion, Title: title, Body: body, TitleDigest: bytesDigest([]byte(title)), BodyDigest: bytesDigest([]byte(body)), ResourceDigest: resourceDigest}
	identity, err := canonicalHash(canonical)
	if err != nil {
		return nil, err
	}
	return &Metadata{version: MetadataVersion, identity: identity, title: title, body: body, titleDigest: canonical.TitleDigest, bodyDigest: canonical.BodyDigest, resourceDigest: resourceDigest}, nil
}

func safeGeneratedMetadata(value string, allowNewline bool) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r == '\n' && allowNewline {
			continue
		}
		if r < 0x20 || r == 0x7f || r > 0x7e {
			return false
		}
	}
	return true
}

func (m *Metadata) Version() string  { return metadataString(m, func() string { return m.version }) }
func (m *Metadata) Identity() string { return metadataString(m, func() string { return m.identity }) }
func (m *Metadata) Title() string    { return metadataString(m, func() string { return m.title }) }
func (m *Metadata) Body() string     { return metadataString(m, func() string { return m.body }) }
func (m *Metadata) TitleDigest() string {
	return metadataString(m, func() string { return m.titleDigest })
}
func (m *Metadata) BodyDigest() string {
	return metadataString(m, func() string { return m.bodyDigest })
}
func (m *Metadata) ResourceDigest() string {
	return metadataString(m, func() string { return m.resourceDigest })
}

func metadataString(m *Metadata, getter func() string) string {
	if m == nil {
		return ""
	}
	return getter()
}
