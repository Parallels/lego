package cloudflare

import (
	"sync"
	"errors"

	"github.com/cloudflare/cloudflare-go"
	"github.com/go-acme/lego/v3/challenge/dns01"
)

type metaClient struct {
	clientEdit *cloudflare.API // needs Zone/DNS/Edit permissions
	clientRead *cloudflare.API // needs Zone/Zone/Read permissions

	zones   map[string]string // caches calls to ZoneIDByName, see lookupZoneID()
	zonesMu *sync.RWMutex
}

func newClient(config *Config) (*metaClient, error) {
	// with AuthKey/AuthEmail we can access all available APIs
	if config.AuthToken == "" {
		client, err := cloudflare.New(config.AuthKey, config.AuthEmail, cloudflare.HTTPClient(config.HTTPClient))
		if err != nil {
			return nil, err
		}

		return &metaClient{
			clientEdit: client,
			clientRead: client,
			zones:      make(map[string]string),
			zonesMu:    &sync.RWMutex{},
		}, nil
	}

	dns, err := cloudflare.NewWithAPIToken(config.AuthToken, cloudflare.HTTPClient(config.HTTPClient))
	if err != nil {
		return nil, err
	}

	if config.ZoneToken == "" || config.ZoneToken == config.AuthToken {
		return &metaClient{
			clientEdit: dns,
			clientRead: dns,
			zones:      make(map[string]string),
			zonesMu:    &sync.RWMutex{},
		}, nil
	}

	zone, err := cloudflare.NewWithAPIToken(config.ZoneToken, cloudflare.HTTPClient(config.HTTPClient))
	if err != nil {
		return nil, err
	}

	return &metaClient{
		clientEdit: dns,
		clientRead: zone,
		zones:      make(map[string]string),
		zonesMu:    &sync.RWMutex{},
	}, nil
}

func (m *metaClient) CreateDNSRecord(zoneID string, rr cloudflare.DNSRecord) (*cloudflare.DNSRecordResponse, error) {
	return m.clientEdit.CreateDNSRecord(zoneID, rr)
}

func (m *metaClient) DNSRecords(zoneID string, rr cloudflare.DNSRecord) ([]cloudflare.DNSRecord, error) {
	return m.clientEdit.DNSRecords(zoneID, rr)
}

func (m *metaClient) DeleteDNSRecord(zoneID, recordID string) error {
	return m.clientEdit.DeleteDNSRecord(zoneID, recordID)
}

func (m *metaClient) ZoneIDByName(fdqn string) (string, error) {
	m.zonesMu.RLock()
	id := m.zones[fdqn]
	m.zonesMu.RUnlock()

	if id != "" {
		return id, nil
	}

	zones, err := m.clientRead.ListZones(dns01.UnFqdn(fdqn))
	if err != nil {
		return "", err
	}

	for _, z := range zones {
		id = z.ID
		break
	}

	if id == "" {
		return "", errors.New("cloudflare dns provider: zone " + fdqn + " not found")
	}

	m.zonesMu.Lock()
	m.zones[fdqn] = id
	m.zonesMu.Unlock()
	return id, nil
}
