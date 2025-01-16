package builders

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/multiversx/mx-chain-core-go/data/transaction"

	"github.com/multiversx/mx-sdk-go/core"
	"github.com/multiversx/mx-sdk-go/data"
)

type relayedTxV2Builder struct {
	innerTransaction                  *transaction.FrontendTransaction
	gasLimitNeededForInnerTransaction uint64
	relayerAccount                    *data.Account
	networkConfig                     *data.NetworkConfig
}

// NewRelayedTxV2Builder creates a new relayed transaction v2 builder
func NewRelayedTxV2Builder() *relayedTxV2Builder {
	return &relayedTxV2Builder{
		innerTransaction: nil,
		relayerAccount:   nil,
		networkConfig:    nil,
	}
}

// SetInnerTransaction sets the inner transaction to be relayed
func (rtb *relayedTxV2Builder) SetInnerTransaction(tx *transaction.FrontendTransaction) *relayedTxV2Builder {
	rtb.innerTransaction = tx

	return rtb
}

// SetRelayerAccount sets the relayer account (that will send the wrapped transaction)
func (rtb *relayedTxV2Builder) SetRelayerAccount(account *data.Account) *relayedTxV2Builder {
	rtb.relayerAccount = account

	return rtb
}

// SetGasLimitNeededForInnerTransaction sets the gas limit needed for the inner transaction
func (rtb *relayedTxV2Builder) SetGasLimitNeededForInnerTransaction(gasLimit uint64) *relayedTxV2Builder {
	rtb.gasLimitNeededForInnerTransaction = gasLimit

	return rtb
}

// SetNetworkConfig sets the network config
func (rtb *relayedTxV2Builder) SetNetworkConfig(config *data.NetworkConfig) *relayedTxV2Builder {
	rtb.networkConfig = config

	return rtb
}

// Build builds the relayed transaction v1
// The returned transaction will not be signed
func (rtb *relayedTxV2Builder) Build() (*transaction.FrontendTransaction, error) {
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
	if rtb.gasLimitNeededForInnerTransaction == 0 {
		return nil, ErrInvalidGasLimitNeededForInnerTransaction
	}
	if rtb.innerTransaction.GasLimit != 0 {
		return nil, ErrGasLimitForInnerTransactionV2ShouldBeZero
	}
	if rtb.innerTransaction.Value != "0" {
		return nil, ErrInvalidValueForInnerTransaction
	}

	innerTxHex, err := prepareInnerTxForRelayV2(rtb.innerTransaction)
	if err != nil {
		return nil, err
	}

	payload := []byte("relayedTxV2@" + innerTxHex)
	gasLimit := rtb.networkConfig.MinGasLimit + rtb.networkConfig.GasPerDataByte*uint64(len(payload)) + rtb.gasLimitNeededForInnerTransaction

	relayedTx := &transaction.FrontendTransaction{
		Nonce:    rtb.relayerAccount.Nonce,
		Value:    rtb.innerTransaction.Value,
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

func prepareInnerTxForRelayV2(tx *transaction.FrontendTransaction) (string, error) {
	nonceBytes := big.NewInt(0).SetUint64(tx.Nonce).Bytes()
	decodedReceiver, err := core.AddressPublicKeyConverter.Decode(tx.Receiver)
	if err != nil {
		return "", err
	}

	payload := fmt.Sprintf("%s@%s@%s@%s",
		hex.EncodeToString(decodedReceiver),
		hex.EncodeToString(nonceBytes),
		hex.EncodeToString(tx.Data),
		tx.Signature,
	)

	return payload, nil
}
