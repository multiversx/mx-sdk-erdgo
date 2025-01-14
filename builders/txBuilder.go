package builders

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/blake2b"
	"github.com/multiversx/mx-chain-core-go/hashing/keccak"
	"github.com/multiversx/mx-chain-core-go/marshal"
	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/multiversx/mx-sdk-go/core"
)

var (
	log                    = logger.GetOrCreate("mx-sdk-go/builders")
	blake2bHasher          = blake2b.NewBlake2b()
	nodeInternalMarshaller = &marshal.GogoProtoMarshalizer{}
	hashSigningTxHasher    = keccak.NewKeccak()
)

type txBuilder struct {
	signer Signer
}

// NewTxBuilder will create a new transaction builder able to build and correctly sign a transaction
func NewTxBuilder(signer Signer) (*txBuilder, error) {
	if check.IfNil(signer) {
		return nil, ErrNilSigner
	}

	return &txBuilder{
		signer: signer,
	}, nil
}

// ApplyUserSignature will apply the corresponding sender and compute and set the user signature field
func (builder *txBuilder) ApplyUserSignature(
	cryptoHolder core.CryptoComponentsHolder,
	tx *transaction.FrontendTransaction,
) error {
	tx.Sender = cryptoHolder.GetBech32()
	unsignedTx := TransactionToUnsignedTx(tx)

	signature, err := builder.signTx(unsignedTx, cryptoHolder)
	if err != nil {
		return err
	}

	tx.Signature = hex.EncodeToString(signature)

	return nil
}

func (builder *txBuilder) signTx(unsignedTx *transaction.FrontendTransaction, userCryptoHolder core.CryptoComponentsHolder) ([]byte, error) {
	// TODO: refactor to use Transaction from core so that GetDataForSigning can be used (this logic is duplicated in core)
	unsignedMessage, err := json.Marshal(unsignedTx)
	if err != nil {
		return nil, err
	}

	shouldSignOnTxHash := unsignedTx.Version >= 2 && unsignedTx.Options&1 > 0
	if shouldSignOnTxHash {
		log.Debug("signing the transaction using the hash of the message")
		unsignedMessage = hashSigningTxHasher.Compute(string(unsignedMessage))
	}

	return builder.signer.SignByteSlice(unsignedMessage, userCryptoHolder.GetPrivateKey())
}

// ApplyGuardianSignature applies the guardian signature over the transaction.
// Does a basic check for the transaction options and guardian address.
func (builder *txBuilder) ApplyGuardianSignature(
	guardianCryptoHolder core.CryptoComponentsHolder,
	tx *transaction.FrontendTransaction,
) error {
	nodeTx, err := transactionToNodeTransaction(tx)
	if err != nil {
		return err
	}

	if !nodeTx.HasOptionGuardianSet() {
		return ErrMissingGuardianOption
	}

	txGuardianAddrBytes, err := core.AddressPublicKeyConverter.Decode(tx.GuardianAddr)
	if err != nil {
		return err
	}

	guardianPubKeyBytes, err := guardianCryptoHolder.GetPublicKey().ToByteArray()
	if err != nil {
		return err
	}

	if !bytes.Equal(txGuardianAddrBytes, guardianPubKeyBytes) {
		return ErrGuardianDoesNotMatch
	}

	unsignedTx := TransactionToUnsignedTx(tx)
	guardianSignature, err := builder.signTx(unsignedTx, guardianCryptoHolder)
	if err != nil {
		return err
	}

	tx.GuardianSignature = hex.EncodeToString(guardianSignature)

	return err
}

// ApplyRelayerSignature applies the relayer signature over the transaction.
// Does a basic check for the relayer address.
func (builder *txBuilder) ApplyRelayerSignature(
	relayerCryptoHolder core.CryptoComponentsHolder,
	tx *transaction.FrontendTransaction,
) error {
	txRelayerAddrBytes, err := core.AddressPublicKeyConverter.Decode(tx.RelayerAddr)
	if err != nil {
		return err
	}

	relayerPubKeyBytes, err := relayerCryptoHolder.GetPublicKey().ToByteArray()
	if err != nil {
		return err
	}

	if !bytes.Equal(txRelayerAddrBytes, relayerPubKeyBytes) {
		return ErrRelayerDoesNotMatch
	}

	unsignedTx := TransactionToUnsignedTx(tx)
	relayerSignature, err := builder.signTx(unsignedTx, relayerCryptoHolder)
	if err != nil {
		return err
	}

	tx.RelayerSignature = hex.EncodeToString(relayerSignature)

	return err
}

// ComputeTxHash will return the hash of the provided transaction. It assumes that the transaction is already signed,
// otherwise it will return an error.
func (builder *txBuilder) ComputeTxHash(tx *transaction.FrontendTransaction) ([]byte, error) {
	if len(tx.Signature) == 0 {
		return nil, ErrMissingSignature
	}

	nodeTx, err := transactionToNodeTransaction(tx)
	if err != nil {
		return nil, err
	}

	txBytes, err := nodeInternalMarshaller.Marshal(nodeTx)
	if err != nil {
		return nil, err
	}

	txHash := blake2bHasher.Compute(string(txBytes))
	return txHash, nil
}

func transactionToNodeTransaction(tx *transaction.FrontendTransaction) (*transaction.Transaction, error) {
	receiverBytes, err := core.AddressPublicKeyConverter.Decode(tx.Receiver)
	if err != nil {
		return nil, err
	}

	senderBytes, err := core.AddressPublicKeyConverter.Decode(tx.Sender)
	if err != nil {
		return nil, err
	}

	signaturesBytes, err := hex.DecodeString(tx.Signature)
	if err != nil {
		return nil, err
	}

	valueBI, ok := big.NewInt(0).SetString(tx.Value, 10)
	if !ok {
		return nil, ErrInvalidValue
	}

	var guardianAddrBytes, guardianSigBytes []byte
	if len(tx.GuardianAddr) > 0 {
		guardianAddrBytes, err = core.AddressPublicKeyConverter.Decode(tx.GuardianAddr)
		if err != nil {
			return nil, err
		}

		guardianSigBytes, err = hex.DecodeString(tx.GuardianSignature)
		if err != nil {
			return nil, err
		}
	}

	var relayerAddrBytes, relayerSigBytes []byte
	if len(tx.RelayerAddr) > 0 {
		relayerAddrBytes, err = core.AddressPublicKeyConverter.Decode(tx.RelayerAddr)
		if err != nil {
			return nil, err
		}

		relayerSigBytes, err = hex.DecodeString(tx.RelayerSignature)
		if err != nil {
			return nil, err
		}
	}

	return &transaction.Transaction{
		Nonce:             tx.Nonce,
		Value:             valueBI,
		RcvAddr:           receiverBytes,
		SndAddr:           senderBytes,
		GasPrice:          tx.GasPrice,
		GasLimit:          tx.GasLimit,
		Data:              tx.Data,
		ChainID:           []byte(tx.ChainID),
		Version:           tx.Version,
		Signature:         signaturesBytes,
		Options:           tx.Options,
		GuardianAddr:      guardianAddrBytes,
		GuardianSignature: guardianSigBytes,
		RelayerAddr:       relayerAddrBytes,
		RelayerSignature:  relayerSigBytes,
	}, nil
}

// TransactionToUnsignedTx returns a shallow clone of the transaction, that has the signature fields set to nil
func TransactionToUnsignedTx(tx *transaction.FrontendTransaction) *transaction.FrontendTransaction {
	unsignedTx := *tx
	unsignedTx.Signature = ""
	unsignedTx.GuardianSignature = ""
	unsignedTx.RelayerSignature = ""

	return &unsignedTx
}

// IsInterfaceNil returns true if there is no value under the interface
func (builder *txBuilder) IsInterfaceNil() bool {
	return builder == nil
}
