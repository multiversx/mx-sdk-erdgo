package nonceHandlerV2

import (
	"context"
	"sync"

	"github.com/ElrondNetwork/elrond-go-core/core"
	"github.com/ElrondNetwork/elrond-go-core/core/check"
	erdgoCore "github.com/ElrondNetwork/elrond-sdk-erdgo/core"
	"github.com/ElrondNetwork/elrond-sdk-erdgo/data"
	"github.com/ElrondNetwork/elrond-sdk-erdgo/interactors"
)

type singleTransactionAddressNonceHandler struct {
	mut                    sync.RWMutex
	address                erdgoCore.AddressHandler
	transaction            *data.Transaction
	gasPrice               uint64
	nonceUntilGasIncreased uint64
	proxy                  interactors.Proxy
}

// NewSingleTransactionAddressNonceHandler returns a new instance of a singleTransactionAddressNonceHandler
func NewSingleTransactionAddressNonceHandler(proxy interactors.Proxy, address erdgoCore.AddressHandler) (*singleTransactionAddressNonceHandler, error) {
	if check.IfNil(proxy) {
		return nil, interactors.ErrNilProxy
	}
	if check.IfNil(address) {
		return nil, interactors.ErrNilAddress
	}
	return &singleTransactionAddressNonceHandler{
		address: address,
		proxy:   proxy,
	}, nil
}

// ApplyNonce will apply the computed nonce to the given ArgCreateTransaction
func (anh *singleTransactionAddressNonceHandler) ApplyNonce(ctx context.Context, txArgs *data.ArgCreateTransaction) error {
	nonce, err := anh.getNonce(ctx)
	if err != nil {
		return err
	}
	txArgs.Nonce = nonce

	anh.fetchGasPriceIfRequired(ctx, nonce)
	txArgs.GasPrice = core.MaxUint64(anh.gasPrice, txArgs.GasPrice)
	return nil
}

func (anh *singleTransactionAddressNonceHandler) fetchGasPriceIfRequired(ctx context.Context, nonce uint64) {
	if nonce == anh.nonceUntilGasIncreased+1 || anh.gasPrice == 0 {
		networkConfig, err := anh.proxy.GetNetworkConfig(ctx)

		anh.mut.Lock()
		defer anh.mut.Unlock()
		if err != nil {
			log.Error("%w: while fetching network config", err)
			anh.gasPrice = 0
			return
		}
		anh.gasPrice = networkConfig.MinGasPrice
	}
}

func (anh *singleTransactionAddressNonceHandler) getNonce(ctx context.Context) (uint64, error) {
	account, err := anh.proxy.GetAccount(ctx, anh.address)
	if err != nil {
		return 0, err
	}

	return account.Nonce, nil
}

// ReSendTransactionsIfRequired will resend the cached transaction if it still has a nonce greater than the one fetched from the blockchain
func (anh *singleTransactionAddressNonceHandler) ReSendTransactionsIfRequired(ctx context.Context) error {
	if anh.transaction == nil {
		return nil
	}
	nonce, err := anh.getNonce(ctx)
	if err != nil {
		return err
	}

	if anh.transaction.Nonce != nonce {
		anh.transaction = nil
		return nil
	}

	hash, err := anh.proxy.SendTransaction(ctx, anh.transaction)
	if err != nil {
		return err
	}

	log.Debug("resent transaction", "address", anh.address.AddressAsBech32String(), "hash", hash)

	return nil
}

// SendTransaction will save and propagate a transaction to the network
func (anh *singleTransactionAddressNonceHandler) SendTransaction(ctx context.Context, tx *data.Transaction) (string, error) {
	anh.mut.Lock()
	anh.transaction = tx
	anh.mut.Unlock()

	return anh.proxy.SendTransaction(ctx, tx)
}

// DropTransactions will delete the cached transaction and will try to replace the current transaction from the pool using more gas price
func (anh *singleTransactionAddressNonceHandler) DropTransactions() {
	anh.mut.Lock()
	defer anh.mut.Unlock()
	anh.gasPrice++
	anh.nonceUntilGasIncreased = anh.transaction.Nonce
	anh.transaction = nil
}
