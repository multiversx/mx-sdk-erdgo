package blockchain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-go/state"
	"github.com/multiversx/mx-sdk-go/blockchain/factory"
	erdgoCore "github.com/multiversx/mx-sdk-go/core"
	erdgoHttp "github.com/multiversx/mx-sdk-go/core/http"
	"github.com/multiversx/mx-sdk-go/data"
)

const (
	withResultsQueryParam = "?withResults=true"
)

// ArgsProxy is the DTO used in the multiversx proxy constructor
type ArgsProxy struct {
	ProxyURL            string
	Client              erdgoHttp.Client
	SameScState         bool
	ShouldBeSynced      bool
	FinalityCheck       bool
	AllowedDeltaToFinal int
	CacheExpirationTime time.Duration
	EntityType          erdgoCore.RestAPIEntityType
}

// multiversXProxy implements basic functions for interacting with a multiversx Proxy
type multiversXProxy struct {
	*baseProxy
	sameScState         bool
	shouldBeSynced      bool
	finalityCheck       bool
	allowedDeltaToFinal int
	finalityProvider    FinalityProvider
}

// NewMultiversXProxy initializes and returns a multiversXProxy object
func NewMultiversXProxy(args ArgsProxy) (*multiversXProxy, error) {
	err := checkArgsProxy(args)
	if err != nil {
		return nil, err
	}

	endpointProvider, err := factory.CreateEndpointProvider(args.EntityType)
	if err != nil {
		return nil, err
	}

	clientWrapper := erdgoHttp.NewHttpClientWrapper(args.Client, args.ProxyURL)
	baseArgs := argsBaseProxy{
		httpClientWrapper: clientWrapper,
		expirationTime:    args.CacheExpirationTime,
		endpointProvider:  endpointProvider,
	}
	baseProxy, err := newBaseProxy(baseArgs)
	if err != nil {
		return nil, err
	}

	finalityProvider, err := factory.CreateFinalityProvider(baseProxy, args.FinalityCheck)
	if err != nil {
		return nil, err
	}

	ep := &multiversXProxy{
		baseProxy:           baseProxy,
		sameScState:         args.SameScState,
		shouldBeSynced:      args.ShouldBeSynced,
		finalityCheck:       args.FinalityCheck,
		allowedDeltaToFinal: args.AllowedDeltaToFinal,
		finalityProvider:    finalityProvider,
	}

	return ep, nil
}

func checkArgsProxy(args ArgsProxy) error {
	if args.FinalityCheck {
		if args.AllowedDeltaToFinal < erdgoCore.MinAllowedDeltaToFinal {
			return fmt.Errorf("%w, provided: %d, minimum: %d",
				ErrInvalidAllowedDeltaToFinal, args.AllowedDeltaToFinal, erdgoCore.MinAllowedDeltaToFinal)
		}
	}

	return nil
}

// ExecuteVMQuery retrieves data from existing SC trie through the use of a VM
func (ep *multiversXProxy) ExecuteVMQuery(ctx context.Context, vmRequest *data.VmValueRequest) (*data.VmValuesResponseData, error) {
	err := ep.checkFinalState(ctx, vmRequest.Address)
	if err != nil {
		return nil, err
	}

	jsonVMRequestWithOptionalParams := data.VmValueRequestWithOptionalParameters{
		VmValueRequest: vmRequest,
		SameScState:    ep.sameScState,
		ShouldBeSynced: ep.shouldBeSynced,
	}
	jsonVMRequest, err := json.Marshal(jsonVMRequestWithOptionalParams)
	if err != nil {
		return nil, err
	}

	buff, code, err := ep.PostHTTP(ctx, ep.endpointProvider.GetVmValues(), jsonVMRequest)
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.ResponseVmValue{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return &response.Data, nil
}

func (ep *multiversXProxy) checkFinalState(ctx context.Context, address string) error {
	if !ep.finalityCheck {
		return nil
	}

	targetShardID, err := ep.GetShardOfAddress(ctx, address)
	if err != nil {
		return err
	}

	return ep.finalityProvider.CheckShardFinalization(ctx, targetShardID, uint64(ep.allowedDeltaToFinal))
}

// GetNetworkEconomics retrieves the network economics from the proxy
func (ep *multiversXProxy) GetNetworkEconomics(ctx context.Context) (*data.NetworkEconomics, error) {
	buff, code, err := ep.GetHTTP(ctx, ep.endpointProvider.GetNetworkEconomics())
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.NetworkEconomicsResponse{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return response.Data.Economics, nil
}

// GetDefaultTransactionArguments will prepare the transaction creation argument by querying the account's info
func (ep *multiversXProxy) GetDefaultTransactionArguments(
	ctx context.Context,
	address erdgoCore.AddressHandler,
	networkConfigs *data.NetworkConfig,
) (data.ArgCreateTransaction, error) {
	if networkConfigs == nil {
		return data.ArgCreateTransaction{}, ErrNilNetworkConfigs
	}
	if check.IfNil(address) {
		return data.ArgCreateTransaction{}, ErrNilAddress
	}

	account, err := ep.GetAccount(ctx, address)
	if err != nil {
		return data.ArgCreateTransaction{}, err
	}

	return data.ArgCreateTransaction{
		Nonce:            account.Nonce,
		Value:            "",
		RcvAddr:          "",
		SndAddr:          address.AddressAsBech32String(),
		GasPrice:         networkConfigs.MinGasPrice,
		GasLimit:         networkConfigs.MinGasLimit,
		Data:             nil,
		Signature:        "",
		ChainID:          networkConfigs.ChainID,
		Version:          networkConfigs.MinTransactionVersion,
		Options:          0,
		AvailableBalance: account.Balance,
	}, nil
}

// GetAccount retrieves an account info from the network (nonce, balance)
func (ep *multiversXProxy) GetAccount(ctx context.Context, address erdgoCore.AddressHandler) (*data.Account, error) {
	err := ep.checkFinalState(ctx, address.AddressAsBech32String())
	if err != nil {
		return nil, err
	}

	if check.IfNil(address) {
		return nil, ErrNilAddress
	}
	if !address.IsValid() {
		return nil, ErrInvalidAddress
	}
	endpoint := ep.endpointProvider.GetAccount(address.AddressAsBech32String())

	buff, code, err := ep.GetHTTP(ctx, endpoint)
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.AccountResponse{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return response.Data.Account, nil
}

// SendTransaction broadcasts a transaction to the network and returns the txhash if successful
func (ep *multiversXProxy) SendTransaction(ctx context.Context, tx *data.Transaction) (string, error) {
	jsonTx, err := json.Marshal(tx)
	if err != nil {
		return "", err
	}
	buff, code, err := ep.PostHTTP(ctx, ep.endpointProvider.GetSendTransaction(), jsonTx)
	if err != nil {
		return "", createHTTPStatusError(code, err)
	}

	response := &data.SendTransactionResponse{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return "", err
	}
	if response.Error != "" {
		return "", errors.New(response.Error)
	}

	return response.Data.TxHash, nil
}

// SendTransactions broadcasts the provided transactions to the network and returns the txhashes if successful
func (ep *multiversXProxy) SendTransactions(ctx context.Context, txs []*data.Transaction) ([]string, error) {
	jsonTx, err := json.Marshal(txs)
	if err != nil {
		return nil, err
	}
	buff, code, err := ep.PostHTTP(ctx, ep.endpointProvider.GetSendMultipleTransactions(), jsonTx)
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.SendTransactionsResponse{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return ep.postProcessSendMultipleTxsResult(response)
}

func (ep *multiversXProxy) postProcessSendMultipleTxsResult(response *data.SendTransactionsResponse) ([]string, error) {
	txHashes := make([]string, 0, len(response.Data.TxsHashes))
	indexes := make([]int, 0, len(response.Data.TxsHashes))
	for index := range response.Data.TxsHashes {
		indexes = append(indexes, index)
	}

	sort.Slice(indexes, func(i, j int) bool {
		return indexes[i] < indexes[j]
	})

	for _, idx := range indexes {
		txHashes = append(txHashes, response.Data.TxsHashes[idx])
	}

	return txHashes, nil
}

// GetTransactionStatus retrieves a transaction's status from the network
func (ep *multiversXProxy) GetTransactionStatus(ctx context.Context, hash string) (string, error) {
	endpoint := ep.endpointProvider.GetTransactionStatus(hash)
	buff, code, err := ep.GetHTTP(ctx, endpoint)
	if err != nil || code != http.StatusOK {
		return "", createHTTPStatusError(code, err)
	}

	response := &data.TransactionStatus{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return "", err
	}
	if response.Error != "" {
		return "", errors.New(response.Error)
	}

	return response.Data.Status, nil
}

// GetTransactionInfo retrieves a transaction's details from the network
func (ep *multiversXProxy) GetTransactionInfo(ctx context.Context, hash string) (*data.TransactionInfo, error) {
	return ep.getTransactionInfo(ctx, hash, false)
}

// GetTransactionInfoWithResults retrieves a transaction's details from the network with events
func (ep *multiversXProxy) GetTransactionInfoWithResults(ctx context.Context, hash string) (*data.TransactionInfo, error) {
	return ep.getTransactionInfo(ctx, hash, true)
}

func (ep *multiversXProxy) getTransactionInfo(ctx context.Context, hash string, withResults bool) (*data.TransactionInfo, error) {
	endpoint := ep.endpointProvider.GetTransactionInfo(hash)
	if withResults {
		endpoint += withResultsQueryParam
	}

	buff, code, err := ep.GetHTTP(ctx, endpoint)
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.TransactionInfo{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return response, nil
}

// RequestTransactionCost retrieves how many gas a transaction will consume
func (ep *multiversXProxy) RequestTransactionCost(ctx context.Context, tx *data.Transaction) (*data.TxCostResponseData, error) {
	jsonTx, err := json.Marshal(tx)
	if err != nil {
		return nil, err
	}
	buff, code, err := ep.PostHTTP(ctx, ep.endpointProvider.GetCostTransaction(), jsonTx)
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.ResponseTxCost{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return &response.Data, nil
}

// GetLatestHyperBlockNonce retrieves the latest hyper block (metachain) nonce from the network
func (ep *multiversXProxy) GetLatestHyperBlockNonce(ctx context.Context) (uint64, error) {
	response, err := ep.GetNetworkStatus(ctx, core.MetachainShardId)
	if err != nil {
		return 0, err
	}

	return response.Nonce, nil
}

// GetHyperBlockByNonce retrieves a hyper block's info by nonce from the network
func (ep *multiversXProxy) GetHyperBlockByNonce(ctx context.Context, nonce uint64) (*data.HyperBlock, error) {
	endpoint := ep.endpointProvider.GetHyperBlockByNonce(nonce)

	return ep.getHyperBlock(ctx, endpoint)
}

// GetHyperBlockByHash retrieves a hyper block's info by hash from the network
func (ep *multiversXProxy) GetHyperBlockByHash(ctx context.Context, hash string) (*data.HyperBlock, error) {
	endpoint := ep.endpointProvider.GetHyperBlockByHash(hash)

	return ep.getHyperBlock(ctx, endpoint)
}

func (ep *multiversXProxy) getHyperBlock(ctx context.Context, endpoint string) (*data.HyperBlock, error) {
	buff, code, err := ep.GetHTTP(ctx, endpoint)
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.HyperBlockResponse{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return &response.Data.HyperBlock, nil
}

// GetRawBlockByHash retrieves a raw block by hash from the network
func (ep *multiversXProxy) GetRawBlockByHash(ctx context.Context, shardId uint32, hash string) ([]byte, error) {
	endpoint := ep.endpointProvider.GetRawBlockByHash(shardId, hash)

	return ep.getRawBlock(ctx, endpoint)
}

// GetRawBlockByNonce retrieves a raw block by hash from the network
func (ep *multiversXProxy) GetRawBlockByNonce(ctx context.Context, shardId uint32, nonce uint64) ([]byte, error) {
	endpoint := ep.endpointProvider.GetRawBlockByNonce(shardId, nonce)

	return ep.getRawBlock(ctx, endpoint)
}

// GetRawStartOfEpochMetaBlock retrieves a raw block by hash from the network
func (ep *multiversXProxy) GetRawStartOfEpochMetaBlock(ctx context.Context, epoch uint32) ([]byte, error) {
	endpoint := ep.endpointProvider.GetRawStartOfEpochMetaBlock(epoch)

	return ep.getRawBlock(ctx, endpoint)
}

func (ep *multiversXProxy) getRawBlock(ctx context.Context, endpoint string) ([]byte, error) {
	buff, code, err := ep.GetHTTP(ctx, endpoint)
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.RawBlockRespone{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return response.Data.Block, nil
}

// GetRawMiniBlockByHash retrieves a raw block by hash from the network
func (ep *multiversXProxy) GetRawMiniBlockByHash(ctx context.Context, shardId uint32, hash string, epoch uint32) ([]byte, error) {
	endpoint := ep.endpointProvider.GetRawMiniBlockByHash(shardId, hash, epoch)

	return ep.getRawMiniBlock(ctx, endpoint)
}

func (ep *multiversXProxy) getRawMiniBlock(ctx context.Context, endpoint string) ([]byte, error) {
	buff, code, err := ep.GetHTTP(ctx, endpoint)
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.RawMiniBlockRespone{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return response.Data.MiniBlock, nil
}

// GetNonceAtEpochStart retrieves the start of epoch nonce from hyper block (metachain)
func (ep *multiversXProxy) GetNonceAtEpochStart(ctx context.Context, shardId uint32) (uint64, error) {
	response, err := ep.GetNetworkStatus(ctx, shardId)
	if err != nil {
		return 0, err
	}

	return response.NonceAtEpochStart, nil
}

// GetRatingsConfig retrieves the ratings configuration from the proxy
func (ep *multiversXProxy) GetRatingsConfig(ctx context.Context) (*data.RatingsConfig, error) {
	buff, code, err := ep.GetHTTP(ctx, ep.endpointProvider.GetRatingsConfig())
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.RatingsConfigResponse{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return response.Data.Config, nil
}

// GetEnableEpochsConfig retrieves the ratings configuration from the proxy
func (ep *multiversXProxy) GetEnableEpochsConfig(ctx context.Context) (*data.EnableEpochsConfig, error) {
	buff, code, err := ep.GetHTTP(ctx, ep.endpointProvider.GetEnableEpochsConfig())
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.EnableEpochsConfigResponse{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return response.Data.Config, nil
}

// GetGenesisNodesPubKeys retrieves genesis nodes configuration from proxy
func (ep *multiversXProxy) GetGenesisNodesPubKeys(ctx context.Context) (*data.GenesisNodes, error) {
	buff, code, err := ep.GetHTTP(ctx, ep.endpointProvider.GetGenesisNodesConfig())
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.GenesisNodesResponse{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return response.Data.Nodes, nil
}

// GetValidatorsInfoByEpoch retrieves the validators info by epoch
func (ep *multiversXProxy) GetValidatorsInfoByEpoch(ctx context.Context, epoch uint32) ([]*state.ShardValidatorInfo, error) {
	buff, code, err := ep.GetHTTP(ctx, ep.endpointProvider.GetValidatorsInfo(epoch))
	if err != nil || code != http.StatusOK {
		return nil, createHTTPStatusError(code, err)
	}

	response := &data.ValidatorsInfoResponse{}
	err = json.Unmarshal(buff, response)
	if err != nil {
		return nil, err
	}
	if response.Error != "" {
		return nil, errors.New(response.Error)
	}

	return response.Data.ValidatorsInfo, nil
}

// IsInterfaceNil returns true if there is no value under the interface
func (ep *multiversXProxy) IsInterfaceNil() bool {
	return ep == nil
}
