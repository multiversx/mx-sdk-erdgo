package notifees

import (
	"context"

	"github.com/multiversx/mx-sdk-go/core"
	"github.com/multiversx/mx-sdk-go/data"
)

// TxBuilder defines the component able to build & sign a transaction
type TxBuilder interface {
	ApplySignatureAndGenerateTx(cryptoHolder core.CryptoComponentsHolder, arg data.ArgCreateTransaction) (*data.Transaction, error)
	IsInterfaceNil() bool
}

// Proxy holds the primitive functions that the multiversx proxy engine supports & implements
// dependency inversion: blockchain package is considered inner business logic, this package is considered "plugin"
type Proxy interface {
	GetNetworkConfig(ctx context.Context) (*data.NetworkConfig, error)
	GetAccount(ctx context.Context, address core.AddressHandler) (*data.Account, error)
	SendTransaction(ctx context.Context, tx *data.Transaction) (string, error)
	SendTransactions(ctx context.Context, txs []*data.Transaction) ([]string, error)
	IsInterfaceNil() bool
}

// TransactionNonceHandler defines the component able to apply nonce for a given ArgCreateTransaction
type TransactionNonceHandler interface {
	ApplyNonceAndGasPrice(ctx context.Context, address core.AddressHandler, txArgs *data.ArgCreateTransaction) error
	SendTransaction(ctx context.Context, tx *data.Transaction) (string, error)
	IsInterfaceNil() bool
}
