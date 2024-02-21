package handler

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"log"
	"math/big"
	"strings"

	"epdg_ue/pkg/ike/context"
	"epdg_ue/pkg/ike/message"
)

// General data
var (
	randomNumberMaximum big.Int
	randomNumberMinimum big.Int
)

func init() {
	randomNumberMaximum.SetString(strings.Repeat("F", 512), 16)
	randomNumberMinimum.SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)
}

func GenerateRandomNumber() *big.Int {
	var number *big.Int
	var err error
	for {
		number, err = rand.Int(rand.Reader, &randomNumberMaximum)
		if err != nil {
			log.Panic("Error occurs when generate random number: %+v", err)
			return nil
		} else {
			if number.Cmp(&randomNumberMinimum) == 1 {
				break
			}
		}
	}
	return number
}

func GenerateRandomUint8() (uint8, error) {
	number := make([]byte, 1)
	_, err := io.ReadFull(rand.Reader, number)
	if err != nil {
		//Errorf("Read random failed: %+v", err)
		return 0, errors.New("Read failed")
	}
	return number[0], nil
}

// Diffie-Hellman Exchange
// The strength supplied by group 1 may not be sufficient for typical uses
const (
	// RFC 2409
	Group1PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
	Group1Generator          = 2
	Group2PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE65381FFFFFFFFFFFFFFFF"
	Group2Generator = 2

	// RFC 3526
	Group5PrimeString         = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
	Group5Generator           = 2
	Group14PrimeString string = "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
		"C4C6628B80DC1CD129024E088A67CC74" +
		"020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F1437" +
		"4FE1356D6D51C245E485B576625E7EC6" +
		"F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE6" +
		"49286651ECE45B3DC2007CB8A163BF05" +
		"98DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB" +
		"9ED529077096966D670C354E4ABC9804" +
		"F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28F" +
		"B5C55DF06F4C52C9DE2BCBF695581718" +
		"3995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	Group14Generator   = 2
	Group15PrimeString = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
	Group15Generator   = 2
	Group16PrimeString = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF"
	Group16Generator   = 2
	Group17PrimeString = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF"
	Group17Generator   = 2
	Group18PrimeString = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF"
	Group18Generator   = 2
)

func CalculateDiffieHellmanMaterials(secret *big.Int, peerPublicValue []byte,
	diffieHellmanGroupNumber uint16) (localPublicValue []byte, sharedKey []byte) {
	peerPublicValueBig := new(big.Int).SetBytes(peerPublicValue)
	var generator, factor *big.Int
	var ok bool

	switch diffieHellmanGroupNumber {
	case message.DH_1024_BIT_MODP:
		generator = new(big.Int).SetUint64(Group2Generator)
		factor, ok = new(big.Int).SetString(Group2PrimeString, 16)
		if !ok {
			//Errorf( "Error occurs when setting big number \"factor\" in %d group", diffieHellmanGroupNumber)
		}
	case message.DH_2048_BIT_MODP:
		generator = new(big.Int).SetUint64(Group14Generator)
		factor, ok = new(big.Int).SetString(Group14PrimeString, 16)
		if !ok {
			//Errorf("Error occurs when setting big number \"factor\" in %d group", diffieHellmanGroupNumber)
		}
	default:
		//Errorf("Unsupported Diffie-Hellman group: %d", diffieHellmanGroupNumber)
		return
	}

	localPublicValue = new(big.Int).Exp(generator, secret, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicValue))
	localPublicValue = append(prependZero, localPublicValue...)

	sharedKey = new(big.Int).Exp(peerPublicValueBig, secret, factor).Bytes()
	prependZero = make([]byte, len(factor.Bytes())-len(sharedKey))
	sharedKey = append(prependZero, sharedKey...)

	return localPublicValue, sharedKey
}

// Pseudorandom Function
func NewPseudorandomFunction(key []byte, algorithmType uint16) (hash.Hash, bool) {
	switch algorithmType {
	case message.PRF_HMAC_MD5:
		return hmac.New(md5.New, key), true
	case message.PRF_HMAC_SHA1:
		return hmac.New(sha1.New, key), true
	default:
		//Errorf("Unsupported pseudo random function: %d", algorithmType)
		return nil, false
	}
}

// Integrity Algorithm
func CalculateChecksum(key []byte, originData []byte, algorithmType uint16) ([]byte, error) {
	switch algorithmType {
	case message.AUTH_HMAC_MD5_96:
		if len(key) != 16 {
			return nil, errors.New("Unmatched input key length")
		}
		integrityFunction := hmac.New(md5.New, key)
		if _, err := integrityFunction.Write(originData); err != nil {
			//Errorf("Hash function write error when calculating checksum: %+v", err)
			return nil, errors.New("Hash function write error")
		}
		return integrityFunction.Sum(nil), nil
	case message.AUTH_HMAC_SHA1_96:
		if len(key) != 20 {
			return nil, errors.New("Unmatched input key length")
		}
		integrityFunction := hmac.New(sha1.New, key)
		if _, err := integrityFunction.Write(originData); err != nil {
			//Errorf("Hash function write error when calculating checksum: %+v", err)
			return nil, errors.New("Hash function write error")
		}
		return integrityFunction.Sum(nil)[:12], nil
	default:
		//Errorf("Unsupported integrity function: %d", algorithmType)
		return nil, errors.New("Unsupported algorithm")
	}
}

func VerifyIKEChecksum(key []byte, originData []byte, checksum []byte, algorithmType uint16) (bool, error) {
	switch algorithmType {
	case message.AUTH_HMAC_MD5_96:
		if len(key) != 16 {
			return false, errors.New("Unmatched input key length")
		}
		integrityFunction := hmac.New(md5.New, key)
		if _, err := integrityFunction.Write(originData); err != nil {
			//Errorf("Hash function write error when verifying IKE checksum: %+v", err)
			return false, errors.New("Hash function write error")
		}
		checksumOfMessage := integrityFunction.Sum(nil)

		//Tracef("Calculated checksum:\n%s\nReceived checksum:\n%s", hex.Dump(checksumOfMessage), hex.Dump(checksum))

		return hmac.Equal(checksumOfMessage, checksum), nil
	case message.AUTH_HMAC_SHA1_96:
		if len(key) != 20 {
			return false, errors.New("Unmatched input key length")
		}
		integrityFunction := hmac.New(sha1.New, key)
		if _, err := integrityFunction.Write(originData); err != nil {
			//Errorf("Hash function write error when verifying IKE checksum: %+v", err)
			return false, errors.New("Hash function write error")
		}
		checksumOfMessage := integrityFunction.Sum(nil)[:12]

		//Tracef("Calculated checksum:\n%s\nReceived checksum:\n%s", hex.Dump(checksumOfMessage), hex.Dump(checksum))

		return hmac.Equal(checksumOfMessage, checksum), nil
	default:
		//Errorf("Unsupported integrity function: %d", algorithmType)
		return false, errors.New("Unsupported algorithm")
	}
}

// Encryption Algorithm
func EncryptMessage(key []byte, originData []byte, algorithmType uint16) ([]byte, error) {
	switch algorithmType {
	case message.ENCR_AES_CBC:
		// padding message
		originData = PKCS7Padding(originData, aes.BlockSize)
		originData[len(originData)-1]--

		block, err := aes.NewCipher(key)
		if err != nil {
			//Errorf("Error occur when create new cipher: %+v", err)
			return nil, errors.New("Create cipher failed")
		}

		cipherText := make([]byte, aes.BlockSize+len(originData))
		initializationVector := cipherText[:aes.BlockSize]

		_, err = io.ReadFull(rand.Reader, initializationVector)
		if err != nil {
			//Errorf("Read random failed: %+v", err)
			return nil, errors.New("Read random initialization vector failed")
		}

		cbcBlockMode := cipher.NewCBCEncrypter(block, initializationVector)
		cbcBlockMode.CryptBlocks(cipherText[aes.BlockSize:], originData)

		return cipherText, nil
	default:
		//Errorf("Unsupported encryption algorithm: %d", algorithmType)
		return nil, errors.New("Unsupported algorithm")
	}
}

func DecryptMessage(key []byte, cipherText []byte, algorithmType uint16) ([]byte, error) {
	switch algorithmType {
	case message.ENCR_AES_CBC:
		if len(cipherText) < aes.BlockSize {
			//Error("Length of cipher text is too short to decrypt")
			return nil, errors.New("Cipher text is too short")
		}

		initializationVector := cipherText[:aes.BlockSize]
		encryptedMessage := cipherText[aes.BlockSize:]

		if len(encryptedMessage)%aes.BlockSize != 0 {
			//Error("Cipher text is not a multiple of block size")
			return nil, errors.New("Cipher text length error")
		}

		plainText := make([]byte, len(encryptedMessage))

		block, err := aes.NewCipher(key)
		if err != nil {
			//Errorf("Error occur when create new cipher: %+v", err)
			return nil, errors.New("Create cipher failed")
		}
		cbcBlockMode := cipher.NewCBCDecrypter(block, initializationVector)
		cbcBlockMode.CryptBlocks(plainText, encryptedMessage)

		//Tracef("Decrypted content:\n%s", hex.Dump(plainText))

		padding := int(plainText[len(plainText)-1]) + 1
		plainText = plainText[:len(plainText)-padding]

		//Tracef("Decrypted content with out padding:\n%s", hex.Dump(plainText))

		return plainText, nil
	default:
		//Errorf("Unsupported encryption algorithm: %d", algorithmType)
		return nil, errors.New("Unsupported algorithm")
	}
}

func PKCS7Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - (len(plainText) % blockSize)
	if padding == 0 {
		padding = blockSize
	}
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plainText, paddingText...)
}

// Key Gen for IKE SA
func GenerateKeyForIKESA(ikeSecurityAssociation *context.IKESecurityAssociation) error {
	// Check parameters
	if ikeSecurityAssociation == nil {
		return errors.New("IKE SA is nil")
	}

	// Check if the context contain needed data
	if ikeSecurityAssociation.EncryptionAlgorithm == nil {
		return errors.New("No encryption algorithm specified")
	}
	if ikeSecurityAssociation.IntegrityAlgorithm == nil {
		return errors.New("No integrity algorithm specified")
	}
	if ikeSecurityAssociation.PseudorandomFunction == nil {
		return errors.New("No pseudorandom function specified")
	}
	if ikeSecurityAssociation.DiffieHellmanGroup == nil {
		return errors.New("No Diffie-hellman group algorithm specified")
	}

	if len(ikeSecurityAssociation.ConcatenatedNonce) == 0 {
		return errors.New("No concatenated nonce data")
	}
	if len(ikeSecurityAssociation.DiffieHellmanSharedKey) == 0 {
		return errors.New("No Diffie-Hellman shared key")
	}

	// Transforms
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction

	// Get key length of SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
	var length_SK_d, length_SK_ai, length_SK_ar, length_SK_ei, length_SK_er, length_SK_pi, length_SK_pr, totalKeyLength int
	var ok bool

	if length_SK_d, ok = getKeyLength(transformPseudorandomFunction.TransformType,
		transformPseudorandomFunction.TransformID, transformPseudorandomFunction.AttributePresent,
		transformPseudorandomFunction.AttributeValue); !ok {
		//Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	if length_SK_ai, ok = getKeyLength(transformIntegrityAlgorithm.TransformType,
		transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent,
		transformIntegrityAlgorithm.AttributeValue); !ok {
		//Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	length_SK_ar = length_SK_ai
	if length_SK_ei, ok = getKeyLength(transformEncryptionAlgorithm.TransformType,
		transformEncryptionAlgorithm.TransformID, transformEncryptionAlgorithm.AttributePresent,
		transformEncryptionAlgorithm.AttributeValue); !ok {
		//Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d
	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4
	var pseudorandomFunction hash.Hash

	if pseudorandomFunction, ok = NewPseudorandomFunction(ikeSecurityAssociation.ConcatenatedNonce,
		transformPseudorandomFunction.TransformID); !ok {
		//Error("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
		return errors.New("New pseudorandom function failed")
	}

	//Tracef("DH shared key:\n%s", hex.Dump(ikeSecurityAssociation.DiffieHellmanSharedKey))
	//Tracef("Concatenated nonce:\n%s", hex.Dump(ikeSecurityAssociation.ConcatenatedNonce))

	if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.DiffieHellmanSharedKey); err != nil {
		//Errorf("Pseudorandom function write error: %+v", err)
		return errors.New("Pseudorandom function write failed")
	}

	SKEYSEED := pseudorandomFunction.Sum(nil)

	//Tracef("SKEYSEED:\n%s", hex.Dump(SKEYSEED))

	seed := concatenateNonceAndSPI(ikeSecurityAssociation.ConcatenatedNonce,
		ikeSecurityAssociation.RemoteSPI, ikeSecurityAssociation.LocalSPI)

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok =
			NewPseudorandomFunction(SKEYSEED, transformPseudorandomFunction.TransformID); !ok {
			//Error("Get an unsupported pseudorandom funcion. This may imply an unsupported transform is chosen.")
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			//Errorf("Pseudorandom function write error: %+v", err)
			return errors.New("Pseudorandom function write failed")
		}
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	// Assign keys into context
	ikeSecurityAssociation.SK_d = keyStream[:length_SK_d]
	keyStream = keyStream[length_SK_d:]
	ikeSecurityAssociation.SK_ai = keyStream[:length_SK_ai]
	keyStream = keyStream[length_SK_ai:]
	ikeSecurityAssociation.SK_ar = keyStream[:length_SK_ar]
	keyStream = keyStream[length_SK_ar:]
	ikeSecurityAssociation.SK_ei = keyStream[:length_SK_ei]
	keyStream = keyStream[length_SK_ei:]
	ikeSecurityAssociation.SK_er = keyStream[:length_SK_er]
	keyStream = keyStream[length_SK_er:]
	ikeSecurityAssociation.SK_pi = keyStream[:length_SK_pi]
	keyStream = keyStream[length_SK_pi:]
	ikeSecurityAssociation.SK_pr = keyStream[:length_SK_pr]
	// keyStream = keyStream[length_SK_pr:]

	//Debugln("====== IKE Security Association Info =====")
	//Debugf("Initiator's SPI: %016x", ikeSecurityAssociation.RemoteSPI)
	//Debugf("Responder's  SPI: %016x", ikeSecurityAssociation.LocalSPI)
	//Debugf("Encryption Algorithm: %d", ikeSecurityAssociation.EncryptionAlgorithm.TransformID)
	//Debugf("SK_ei: %x", ikeSecurityAssociation.SK_ei)
	//Debugf("SK_er: %x", ikeSecurityAssociation.SK_er)
	//Debugf("Integrity Algorithm: %d", ikeSecurityAssociation.IntegrityAlgorithm.TransformID)
	//Debugf("SK_ai: %x", ikeSecurityAssociation.SK_ai)
	//Debugf("SK_ar: %x", ikeSecurityAssociation.SK_ar)
	//Debugf("SK_pi: %x", ikeSecurityAssociation.SK_pi)
	//Debugf("SK_pr: %x", ikeSecurityAssociation.SK_pr)

	return nil
}

// Decrypt
func DecryptProcedure(ikeSecurityAssociation *context.IKESecurityAssociation, ikeMessage *message.IKEMessage,
	encryptedPayload *message.Encrypted) (message.IKEPayloadContainer, error) {
	// Check parameters
	if ikeSecurityAssociation == nil {
		return nil, errors.New("IKE SA is nil")
	}
	if ikeMessage == nil {
		return nil, errors.New("IKE message is nil")
	}
	if encryptedPayload == nil {
		return nil, errors.New("IKE encrypted payload is nil")
	}

	// Check if the context contain needed data
	if ikeSecurityAssociation.IntegrityAlgorithm == nil {
		return nil, errors.New("No integrity algorithm specified")
	}
	if ikeSecurityAssociation.EncryptionAlgorithm == nil {
		return nil, errors.New("No encryption algorithm specified")
	}

	if len(ikeSecurityAssociation.SK_ai) == 0 {
		return nil, errors.New("No initiator's integrity key")
	}
	if len(ikeSecurityAssociation.SK_ei) == 0 {
		return nil, errors.New("No initiator's encryption key")
	}

	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	checksumLength, ok := getOutputLength(transformIntegrityAlgorithm.TransformType,
		transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent,
		transformIntegrityAlgorithm.AttributeValue)
	if !ok {
		//Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return nil, errors.New("Get key length failed")
	}

	// Checksum
	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-checksumLength:]

	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		//Errorln(err)
		//Error("Error occur when encoding for checksum")
		return nil, errors.New("Encoding IKE message failed")
	}

	ok, err = VerifyIKEChecksum(ikeSecurityAssociation.SK_ai,
		ikeMessageData[:len(ikeMessageData)-checksumLength], checksum,
		transformIntegrityAlgorithm.TransformID)
	if err != nil {
		//Errorf("Error occur when verifying checksum: %+v", err)
		return nil, errors.New("Error verify checksum")
	}
	if !ok {
		//Warn("Message checksum failed. Drop the message.")
		return nil, errors.New("Checksum failed, drop.")
	}

	// Decrypt
	encryptedData := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-checksumLength]
	plainText, err := DecryptMessage(ikeSecurityAssociation.SK_ei, encryptedData,
		transformEncryptionAlgorithm.TransformID)
	if err != nil {
		//Errorf("Error occur when decrypting message: %+v", err)
		return nil, errors.New("Error decrypting message")
	}

	var decryptedIKEPayload message.IKEPayloadContainer
	err = decryptedIKEPayload.Decode(encryptedPayload.NextPayload, plainText)
	if err != nil {
		//Errorln(err)
		return nil, errors.New("Decoding decrypted payload failed")
	}

	return decryptedIKEPayload, nil
}

// Encrypt
func EncryptProcedure(ikeSecurityAssociation *context.IKESecurityAssociation,
	ikePayload message.IKEPayloadContainer, responseIKEMessage *message.IKEMessage) error {
	// Check parameters
	if ikeSecurityAssociation == nil {
		return errors.New("IKE SA is nil")
	}
	if len(ikePayload) == 0 {
		return errors.New("No IKE payload to be encrypted")
	}
	if responseIKEMessage == nil {
		return errors.New("Response IKE message is nil")
	}

	// Check if the context contain needed data
	if ikeSecurityAssociation.IntegrityAlgorithm == nil {
		return errors.New("No integrity algorithm specified")
	}
	if ikeSecurityAssociation.EncryptionAlgorithm == nil {
		return errors.New("No encryption algorithm specified")
	}

	if len(ikeSecurityAssociation.SK_ar) == 0 {
		return errors.New("No responder's integrity key")
	}
	if len(ikeSecurityAssociation.SK_er) == 0 {
		return errors.New("No responder's encryption key")
	}

	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	checksumLength, ok := getOutputLength(transformIntegrityAlgorithm.TransformType,
		transformIntegrityAlgorithm.TransformID, transformIntegrityAlgorithm.AttributePresent,
		transformIntegrityAlgorithm.AttributeValue)
	if !ok {
		//Error("Get key length of an unsupported algorithm. This may imply an unsupported transform is chosen.")
		return errors.New("Get key length failed")
	}

	// Encrypting
	ikePayloadData, err := ikePayload.Encode()
	if err != nil {
		//Error(err)
		return errors.New("Encoding IKE payload failed.")
	}

	encryptedData, err := EncryptMessage(ikeSecurityAssociation.SK_er, ikePayloadData,
		transformEncryptionAlgorithm.TransformID)
	if err != nil {
		//Errorf("Encrypting data error: %+v", err)
		return errors.New("Error encrypting message")
	}

	encryptedData = append(encryptedData, make([]byte, checksumLength)...)
	sk := responseIKEMessage.Payloads.BuildEncrypted(ikePayload[0].Type(), encryptedData)

	// Calculate checksum
	responseIKEMessageData, err := responseIKEMessage.Encode()
	if err != nil {
		//Error(err)
		return errors.New("Encoding IKE message error")
	}
	checksumOfMessage, err := CalculateChecksum(ikeSecurityAssociation.SK_ar,
		responseIKEMessageData[:len(responseIKEMessageData)-checksumLength],
		transformIntegrityAlgorithm.TransformID)
	if err != nil {
		//Errorf("Calculating checksum failed: %+v", err)
		return errors.New("Error calculating checksum")
	}
	checksumField := sk.EncryptedData[len(sk.EncryptedData)-checksumLength:]
	copy(checksumField, checksumOfMessage)

	return nil
}

// Get information of algorithm
func getKeyLength(transformType uint8, transformID uint16, attributePresent bool,
	attributeValue uint16) (int, bool) {
	switch transformType {
	case message.TypeEncryptionAlgorithm:
		switch transformID {
		case message.ENCR_DES_IV64:
			return 0, false
		case message.ENCR_DES:
			return 8, true
		case message.ENCR_3DES:
			return 24, true
		case message.ENCR_RC5:
			return 0, false
		case message.ENCR_IDEA:
			return 0, false
		case message.ENCR_CAST:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 16, true
				case 256:
					return 0, false
				default:
					return 0, false
				}
			}
			return 0, false
		case message.ENCR_BLOWFISH: // Blowfish support variable key length
			if attributePresent {
				if attributeValue < 40 {
					return 0, false
				} else if attributeValue > 448 {
					return 0, false
				} else {
					return int(attributeValue / 8), true
				}
			} else {
				return 0, false
			}
		case message.ENCR_3IDEA:
			return 0, false
		case message.ENCR_DES_IV32:
			return 0, false
		case message.ENCR_NULL:
			return 0, true
		case message.ENCR_AES_CBC:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 16, true
				case 192:
					return 24, true
				case 256:
					return 32, true
				default:
					return 0, false
				}
			} else {
				return 0, false
			}
		case message.ENCR_AES_CTR:
			if attributePresent {
				switch attributeValue {
				case 128:
					return 20, true
				case 192:
					return 28, true
				case 256:
					return 36, true
				default:
					return 0, false
				}
			} else {
				return 0, false
			}
		default:
			return 0, false
		}
	case message.TypePseudorandomFunction:
		switch transformID {
		case message.PRF_HMAC_MD5:
			return 16, true
		case message.PRF_HMAC_SHA1:
			return 20, true
		case message.PRF_HMAC_TIGER:
			return 0, false
		default:
			return 0, false
		}
	case message.TypeIntegrityAlgorithm:
		switch transformID {
		case message.AUTH_NONE:
			return 0, false
		case message.AUTH_HMAC_MD5_96:
			return 16, true
		case message.AUTH_HMAC_SHA1_96:
			return 20, true
		case message.AUTH_DES_MAC:
			return 0, false
		case message.AUTH_KPDK_MD5:
			return 0, false
		case message.AUTH_AES_XCBC_96:
			return 0, false
		default:
			return 0, false
		}
	case message.TypeDiffieHellmanGroup:
		switch transformID {
		case message.DH_NONE:
			return 0, false
		case message.DH_768_BIT_MODP:
			return 0, false
		case message.DH_1024_BIT_MODP:
			return 0, false
		case message.DH_1536_BIT_MODP:
			return 0, false
		case message.DH_2048_BIT_MODP:
			return 0, false
		case message.DH_3072_BIT_MODP:
			return 0, false
		case message.DH_4096_BIT_MODP:
			return 0, false
		case message.DH_6144_BIT_MODP:
			return 0, false
		case message.DH_8192_BIT_MODP:
			return 0, false
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

func getOutputLength(transformType uint8, transformID uint16, attributePresent bool,
	attributeValue uint16) (int, bool) {
	switch transformType {
	case message.TypePseudorandomFunction:
		switch transformID {
		case message.PRF_HMAC_MD5:
			return 16, true
		case message.PRF_HMAC_SHA1:
			return 20, true
		case message.PRF_HMAC_TIGER:
			return 0, false
		default:
			return 0, false
		}
	case message.TypeIntegrityAlgorithm:
		switch transformID {
		case message.AUTH_NONE:
			return 0, false
		case message.AUTH_HMAC_MD5_96:
			return 12, true
		case message.AUTH_HMAC_SHA1_96:
			return 12, true
		case message.AUTH_DES_MAC:
			return 0, false
		case message.AUTH_KPDK_MD5:
			return 0, false
		case message.AUTH_AES_XCBC_96:
			return 0, false
		default:
			return 0, false
		}
	default:
		return 0, false
	}
}

func concatenateNonceAndSPI(nonce []byte, SPI_initiator uint64, SPI_responder uint64) []byte {
	spi := make([]byte, 8)

	binary.BigEndian.PutUint64(spi, SPI_initiator)
	newSlice := append(nonce, spi...)
	binary.BigEndian.PutUint64(spi, SPI_responder)
	newSlice = append(newSlice, spi...)

	return newSlice
}
