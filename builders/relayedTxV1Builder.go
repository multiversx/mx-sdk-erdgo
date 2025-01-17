package builders

import (
	"encoding/hex"
	"encoding/json"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/data/transaction"

	"github.com/multiversx/mx-sdk-go/core"
	"github.com/multiversx/mx-sdk-go/data"
)

type relayedTxV1Builder struct {
	innerTransaction *transaction.FrontendTransaction
	relayerAccount   *data.Account
	networkConfig    *data.NetworkConfig
}

// NewRelayedTxV1Builder creates a new relayed transaction v1 builder
func NewRelayedTxV1Builder() RelayedTxV1Builder {
	return &relayedTxV1Builder{
		innerTransaction: nil,
		relayerAccount:   nil,
		networkConfig:    nil,
	}
}

// SetInnerTransaction sets the inner transaction to be relayed
func (rtb *relayedTxV1Builder) SetInnerTransaction(tx *transaction.FrontendTransaction) RelayedTxV1Builder {
	rtb.innerTransaction = tx

	return rtb
}

// SetRelayerAccount sets the relayer account
func (rtb *relayedTxV1Builder) SetRelayerAccount(account *data.Account) RelayedTxV1Builder {
	rtb.relayerAccount = account

	return rtb
}

// SetNetworkConfig sets the network config
func (rtb *relayedTxV1Builder) SetNetworkConfig(config *data.NetworkConfig) RelayedTxV1Builder {
	rtb.networkConfig = config

	return rtb
}

// Build builds the relayed transaction v1
// The returned transaction will not be signed
func (rtb *relayedTxV1Builder) Build() (*transaction.FrontendTransaction, error) {
	if rtb.innerTransaction == nil {
		return nil, ErrNilInnerTransaction
	}
	if len(rtb.innerTransaction.Signature) == 0 {
		return nil, ErrNilInnerTransactionSignature
	}
	if rtb.relayerAccount == nil {
		return nil, ErrNilRelayerAccount
	}
	if rtb.networkConfig == nil {
		return nil, ErrNilNetworkConfig
	}

	innerTxHex, err := prepareInnerTxForRelayV1(rtb.innerTransaction)
	if err != nil {
		return nil, err
	}

	payload := []byte("relayedTx@" + innerTxHex)
	gasLimit := rtb.networkConfig.MinGasLimit + rtb.networkConfig.GasPerDataByte*uint64(len(payload)) + rtb.innerTransaction.GasLimit

	innerTxValue, ok := big.NewInt(0).SetString(rtb.innerTransaction.Value, 10)
	if !ok {
		return nil, ErrInvalidValue
	}

	relayedTx := &transaction.FrontendTransaction{
		Nonce:    rtb.relayerAccount.Nonce,
		Value:    innerTxValue.String(),
		Receiver: rtb.innerTransaction.Sender,
		Sender:   rtb.relayerAccount.Address,
		GasPrice: rtb.innerTransaction.GasPrice,
		GasLimit: gasLimit,
		Data:     payload,
		ChainID:  rtb.networkConfig.ChainID,
		Version:  rtb.networkConfig.MinTransactionVersion,
	}

	return relayedTx, nil
}

func prepareInnerTxForRelayV1(tx *transaction.FrontendTransaction) (string, error) {
	txValue, ok := big.NewInt(0).SetString(tx.Value, 10)
	if !ok {
		return "", ErrInvalidValue
	}

	addressConverter := core.AddressPublicKeyConverter
	receiverAddress, err := addressConverter.Decode(tx.Receiver)
	if err != nil {
		return "", err
	}

	senderAddress, err := addressConverter.Decode(tx.Sender)
	if err != nil {
		return "", err
	}

	signatureBytes, err := hex.DecodeString(tx.Signature)
	if err != nil {
		return "", err
	}

	// TODO: remove this hardcoded implementation. Inside mx-chain-core-go, create there a dedicated converter between FrontendTransaction <-> Transaction
	coreTx := &transaction.Transaction{
		Nonce:     tx.Nonce,
		Value:     txValue,
		RcvAddr:   receiverAddress,
		SndAddr:   senderAddress,
		GasPrice:  tx.GasPrice,
		GasLimit:  tx.GasLimit,
		Data:      tx.Data,
		ChainID:   []byte(tx.ChainID),
		Version:   tx.Version,
		Signature: signatureBytes,
		Options:   tx.Options,
	}

	serializedTx, err := json.Marshal(coreTx)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(serializedTx), nil
}
