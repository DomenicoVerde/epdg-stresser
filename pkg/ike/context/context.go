package context

import "epdg_ue/pkg/ike/message"

type IKESecurityAssociation struct {
	// SPI
	RemoteSPI uint64
	LocalSPI  uint64

	// Message ID
	InitiatorMessageID uint32
	ResponderMessageID uint32

	// Transforms for IKE SA
	EncryptionAlgorithm    *message.Transform
	PseudorandomFunction   *message.Transform
	IntegrityAlgorithm     *message.Transform
	DiffieHellmanGroup     *message.Transform
	ExpandedSequenceNumber *message.Transform

	// Used for key generating
	ConcatenatedNonce      []byte
	DiffieHellmanSharedKey []byte

	// Keys
	SK_d  []byte // used for child SA key deriving
	SK_ai []byte // used by initiator for integrity checking
	SK_ar []byte // used by responder for integrity checking
	SK_ei []byte // used by initiator for encrypting
	SK_er []byte // used by responder for encrypting
	SK_pi []byte // used by initiator for IKE authentication
	SK_pr []byte // used by responder for IKE authentication

	// State for IKE_AUTH
	State uint8

	// Temporary data stored for the use in later exchange
	InitiatorID              *message.IdentificationInitiator
	InitiatorCertificate     *message.Certificate
	IKEAuthResponseSA        *message.SecurityAssociation
	TrafficSelectorInitiator *message.TrafficSelectorInitiator
	TrafficSelectorResponder *message.TrafficSelectorResponder
	LastEAPIdentifier        uint8

	// Authentication data
	LocalUnsignedAuthentication  []byte
	RemoteUnsignedAuthentication []byte

	// NAT detection
	UEIsBehindNAT   bool
	EPDGIsBehindNAT bool
}
