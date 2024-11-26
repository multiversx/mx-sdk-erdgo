package interactors_test

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/ElrondNetwork/elrond-go-crypto/signing"
	"github.com/ElrondNetwork/elrond-go-crypto/signing/ed25519"
	"github.com/btcsuite/btcutil/bech32"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
)

const (
	bip32EgldCoinType = uint32(508)
	bip32Hardened     = uint32(0x80000000)
	publicKeyLength   = 32
	bech32Hrp         = "erd"
	bech32FromBits    = byte(8)
	bech32ToBits      = byte(5)
	bech32Pad         = true
)

var (
	suite        = ed25519.NewEd25519()
	keyGenerator = signing.NewKeyGenerator(suite)
)

type bip32Path []uint32

type bip32 struct {
	key       []byte
	chainCode []byte
}

type generatedKey struct {
	AccountIndex int
	AddressIndex int
	SecretKey    []byte
	PublicKey    []byte
	Address      string
}

func Test_GenerateKeysInProjectedShard(t *testing.T) {
	projectedShard := byte(0)

	// A test mnemonic: https://raw.githubusercontent.com/ElrondNetwork/elrond-sdk-testwallets/main/users/mnemonic.txt
	mnemonic := "moral volcano peasant pass circle pen over picture flat shop clap goat never lyrics gather prepare woman film husband gravity behind test tiger improve"
	seed := bip39.NewSeed(string(mnemonic), "")

	firstIndex := 0
	lastIndex := 5000
	// We are going to use "addressIndex" for HD keys generation
	useAccountIndex := false

	keys, err := generateKeysInProjectedShard(projectedShard, seed, firstIndex, lastIndex, useAccountIndex)
	require.Nil(t, err)

	// Cross-checked with https://github.com/ElrondNetwork/elrond-tools-go/pull/21
	require.Equal(t, "erd1ldjsdetjvegjdnda0qw2h62kq6rpvrklkc5pw9zxm0nwulfhtyqqtyc4vq", keys[0].Address)
	require.Equal(t, "erd1xtslmt67utuewwv8jsx729mxjxaa8dvyyzp7492hy99dl7hvcuqq30l98v", keys[1].Address)
	require.Equal(t, "erd1j8j3hqtc5zu6l7lcl73q5mc06vzyxtrfrexrnvjs0z6v4se7myqqwkl0qq", keys[2].Address)

	for _, key := range keys {
		fmt.Println(
			"Account", key.AccountIndex,
			"Address", key.AddressIndex,
			"Address", key.Address,
			"Secret key", hex.EncodeToString(key.SecretKey),
		)
	}

	fmt.Println("Number of generated keys:", len(keys))
}

func generateKeysInProjectedShard(projectedShard byte, seed []byte, firstIndex int, lastIndex int, useAccountIndex bool) ([]generatedKey, error) {
	goodKeys := make([]generatedKey, 0)

	accountIndex := 0
	addressIndex := 0
	var changingIndex *int

	// Usually, we derive different keys (accounts) by incrementing the "addressIndex", but "accountIndex" can also be used.
	if useAccountIndex {
		changingIndex = &accountIndex
	} else {
		changingIndex = &addressIndex
	}

	for i := firstIndex; i < lastIndex; i++ {
		*changingIndex = i

		secretKey := getPrivateKeyFromSeed(seed, uint32(accountIndex), uint32(addressIndex))
		publicKey, err := getPublicKeyFromPrivateKey(secretKey)
		if err != nil {
			return nil, err
		}

		isGoodKey := belongsToProjectedShard(publicKey, projectedShard)
		if isGoodKey {
			address, err := getAddressFromPublicKey(publicKey)
			if err != nil {
				return nil, err
			}

			goodKeys = append(goodKeys, generatedKey{
				AccountIndex: accountIndex,
				AddressIndex: addressIndex,
				SecretKey:    secretKey,
				PublicKey:    publicKey,
				Address:      address,
			})
		}
	}

	return goodKeys, nil
}

// Extracted from: https://github.com/ElrondNetwork/elrond-sdk-erdgo/blob/main/interactors/wallet.go#L105
func getPrivateKeyFromSeed(seed []byte, accountIndex uint32, addressIndex uint32) []byte {
	var egldPath = bip32Path{
		44 | bip32Hardened,
		bip32EgldCoinType | bip32Hardened,
		bip32Hardened, // accountIndex
		bip32Hardened,
		bip32Hardened, // addressIndex
	}

	egldPath[2] = accountIndex | bip32Hardened
	egldPath[4] = addressIndex | bip32Hardened
	keyData := derivePrivateKey(seed, egldPath)

	return keyData.key
}

// Extracted from: https://github.com/ElrondNetwork/elrond-sdk-erdgo/blob/main/interactors/wallet.go#L127
func derivePrivateKey(seed []byte, path bip32Path) *bip32 {
	b := &bip32{}
	digest := hmac.New(sha512.New, []byte("ed25519 seed"))
	digest.Write(seed)
	intermediary := digest.Sum(nil)
	serializedKeyLen := 32
	serializedChildIndexLen := 4
	hardenedChildPadding := byte(0x00)
	b.key = intermediary[:serializedKeyLen]
	b.chainCode = intermediary[serializedKeyLen:]
	for _, childIdx := range path {
		buff := make([]byte, 1+serializedKeyLen+4)
		buff[0] = hardenedChildPadding
		copy(buff[1:1+serializedKeyLen], b.key)
		binary.BigEndian.PutUint32(buff[1+serializedKeyLen:1+serializedKeyLen+serializedChildIndexLen], childIdx)
		digest = hmac.New(sha512.New, b.chainCode)
		digest.Write(buff)
		intermediary = digest.Sum(nil)
		b.key = intermediary[:serializedKeyLen]
		b.chainCode = intermediary[serializedKeyLen:]
	}

	return b
}

// Extracted from: https://github.com/ElrondNetwork/elrond-sdk-erdgo/blob/main/interactors/wallet.go#L153
func getPublicKeyFromPrivateKey(privateKeyBytes []byte) ([]byte, error) {
	privateKey, err := keyGenerator.PrivateKeyFromByteArray(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.GeneratePublic()
	publicKeyBytes, err := publicKey.ToByteArray()
	if err != nil {
		return nil, err
	}

	return publicKeyBytes, nil
}

// Extracted from: https://github.com/ElrondNetwork/elrond-go-core/blob/main/core/pubkeyConverter/bech32PubkeyConverter.go#L83
func getAddressFromPublicKey(publicKey []byte) (string, error) {
	if len(publicKey) != publicKeyLength {
		return "", errors.New("bad length of public key")
	}

	conv, err := bech32.ConvertBits(publicKey, bech32FromBits, bech32ToBits, bech32Pad)
	if err != nil {
		return "", err
	}

	address, err := bech32.Encode(bech32Hrp, conv)
	if err != nil {
		return "", err
	}

	return address, nil
}

func belongsToProjectedShard(publicKey []byte, projectedShard byte) bool {
	return publicKey[publicKeyLength-1] == projectedShard
}

func Test_DecodeAddress(t *testing.T) {
	pubkey, err := decodeAddress("erd1ldjsdetjvegjdnda0qw2h62kq6rpvrklkc5pw9zxm0nwulfhtyqqtyc4vq")
	require.Nil(t, err)
	require.Equal(t, "fb6506e572665126cdbd781cabe9560686160edfb628171446dbe6ee7d375900", hex.EncodeToString(pubkey))

	pubkey, err = decodeAddress("erd1xtslmt67utuewwv8jsx729mxjxaa8dvyyzp7492hy99dl7hvcuqq30l98v")
	require.Nil(t, err)
	require.Equal(t, "32e1fdaf5ee2f9973987940de5176691bbd3b5842083ea9557214adffaecc700", hex.EncodeToString(pubkey))

	pubkey, err = decodeAddress("erd1j8j3hqtc5zu6l7lcl73q5mc06vzyxtrfrexrnvjs0z6v4se7myqqwkl0qq")
	require.Nil(t, err)
	require.Equal(t, "91e51b8178a0b9affbf8ffa20a6f0fd304432c691e4c39b25078b4cac33ed900", hex.EncodeToString(pubkey))

	pubkey, err = decodeAddress("erd2j8j3hqtc5zu6l7lcl73q5mc06vzyxtrfrexrnvjs0z6v4se7myqqwkl0qq")
	require.NotNil(t, err)
	require.Nil(t, pubkey)

	pubkey, err = decodeAddress("eee1j8j3hqtc5zu6l7lcl73q5mc06vzyxtrfrexrnvjs0z6v4se7myqqwkl0qq")
	require.NotNil(t, err)
	require.Nil(t, pubkey)

	pubkey, err = decodeAddress("erd1ldjsdetjvegjdnda0qw2h62kq6rpvrklkc5pw9zxm0nwulfhtyqqtyc4v0")
	require.NotNil(t, err)
	require.Nil(t, pubkey)
}

// Extracted from: https://github.com/ElrondNetwork/elrond-go-core/blob/main/core/pubkeyConverter/bech32PubkeyConverter.go#L59
func decodeAddress(humanReadable string) ([]byte, error) {
	decodedPrefix, buff, err := bech32.Decode(humanReadable)
	if err != nil {
		return nil, err
	}
	if decodedPrefix != bech32Hrp {
		return nil, errors.New("bad address")
	}

	decodedBytes, err := bech32.ConvertBits(buff, bech32ToBits, bech32FromBits, !bech32Pad)
	if err != nil {
		return nil, errors.New("bad address")
	}

	if len(decodedBytes) != publicKeyLength {
		return nil, errors.New("bad length of public key")
	}

	return decodedBytes, nil
}
