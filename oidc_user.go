package siauth

import (
	"errors"
	"fmt"
	"time"

	"github.com/germtb/sidb"
	"google.golang.org/protobuf/proto"
)

var ErrOIDCMappingNotFound = errors.New("OIDC user mapping not found")

// OIDCUserMapping stores the relationship between OIDC provider identities and local users
type OIDCUserMapping struct {
	ProviderName string // e.g., "google", "github"
	ProviderSub  string // Provider's unique user ID
	Username     string // Local username
	CreatedAt    int64  // Unix milliseconds
}

// OIDCUserMappingStore manages OIDC identity mappings
type OIDCUserMappingStore struct {
	store *sidb.Store[*ProtoOIDCUserMapping]
}

func MakeOIDCUserMappingStore(namespace string) (*OIDCUserMappingStore, error) {
	db, err := sidb.Init([]string{namespace}, "oidc_mappings")
	if err != nil {
		return nil, err
	}

	store := sidb.MakeStore(db, "oidc_mapping", serialize, deserializeOIDCMapping, nil)

	return &OIDCUserMappingStore{
		store: store,
	}, nil
}

// LinkIdentity creates a mapping between an OIDC identity and a local user
func (s *OIDCUserMappingStore) LinkIdentity(providerName, providerSub, username string) error {
	key := makeOIDCMappingKey(providerName, providerSub)

	mapping := &ProtoOIDCUserMapping{
		ProviderName: providerName,
		ProviderSub:  providerSub,
		Username:     username,
		CreatedAt:    time.Now().UnixMilli(),
	}

	return s.store.Upsert(sidb.StoreEntryInput[*ProtoOIDCUserMapping]{
		Key:   key,
		Value: mapping,
	})
}

// GetUsername retrieves the local username for a given OIDC identity
func (s *OIDCUserMappingStore) GetUsername(providerName, providerSub string) (string, error) {
	key := makeOIDCMappingKey(providerName, providerSub)

	mapping, err := s.store.Get(key)
	if err != nil {
		return "", err
	}

	if mapping == nil {
		return "", ErrOIDCMappingNotFound
	}

	return mapping.Username, nil
}

// GetIdentities retrieves all OIDC identities linked to a local user
func (s *OIDCUserMappingStore) GetIdentities(username string) ([]*OIDCUserMapping, error) {
	// Query all mappings - sidb doesn't have reverse lookup, so we scan all
	// This is acceptable as the number of mappings per user is typically small
	entries, err := s.store.Query(sidb.StoreQueryParams{
		Limit:  func() *int { l := 1000; return &l }(), // Reasonable upper bound
		Offset: func() *int { o := 0; return &o }(),
	})

	if err != nil {
		return nil, err
	}

	var identities []*OIDCUserMapping
	for _, entry := range entries {
		if entry.Username == username {
			identities = append(identities, &OIDCUserMapping{
				ProviderName: entry.ProviderName,
				ProviderSub:  entry.ProviderSub,
				Username:     entry.Username,
				CreatedAt:    entry.CreatedAt,
			})
		}
	}

	return identities, nil
}

// UnlinkIdentity removes a mapping between an OIDC identity and a local user
func (s *OIDCUserMappingStore) UnlinkIdentity(providerName, providerSub string) error {
	key := makeOIDCMappingKey(providerName, providerSub)
	return s.store.Delete(key)
}

// makeOIDCMappingKey generates a composite key for OIDC mappings
func makeOIDCMappingKey(providerName, providerSub string) string {
	return fmt.Sprintf("%s:%s", providerName, providerSub)
}

// deserializeOIDCMapping deserializes a protobuf OIDC mapping
func deserializeOIDCMapping(data []byte) (*ProtoOIDCUserMapping, error) {
	var mapping ProtoOIDCUserMapping
	err := proto.Unmarshal(data, &mapping)
	if err != nil {
		return nil, err
	}
	return &mapping, nil
}
