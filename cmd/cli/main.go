package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	logger "github.com/multiversx/mx-chain-logger-go"
	"github.com/multiversx/mx-sdk-go/blockchain"
	"github.com/multiversx/mx-sdk-go/blockchain/cryptoProvider"
	"github.com/multiversx/mx-sdk-go/builders"
	"github.com/multiversx/mx-sdk-go/core"
	"github.com/multiversx/mx-sdk-go/data"
	"github.com/multiversx/mx-sdk-go/examples"
	"github.com/multiversx/mx-sdk-go/interactors"
	"github.com/multiversx/mx-sdk-go/workflows"
	"github.com/urfave/cli"
)

var (
	helpTemplate = `NAME:
   {{.Name}} - {{.Usage}}
USAGE:
   {{.HelpName}} {{if .VisibleFlags}}[global options]{{end}}
   {{if len .Authors}}
AUTHOR:
   {{range .Authors}}{{ . }}{{end}}
   {{end}}{{if .Commands}}
GLOBAL OPTIONS:
   {{range .VisibleFlags}}{{.}}
   {{end}}
VERSION:
   {{.Version}}
   {{end}}
`
	setGuardianUID = "serviceUID"

	guardedTxBy = cli.StringFlag{
		Name:        "guardedTxBy",
		Usage:       "If used, will set the guardian to the given one. Options: alice, bob, eve, charlie",
		Destination: &argsConfig.guardedTxBy,
	}

	setGuardian = cli.StringFlag{
		Name:        "setGuardian",
		Usage:       "If used, it fills the data field with formatted setGuardian transaction data for the given guardian address. Options: alice, bob, eve, charlie, erd1..... Could fail with custom address and guardedTx set",
		Destination: &argsConfig.guardian,
	}

	sender = cli.StringFlag{
		Name:        "sender",
		Usage:       "If used, it replaces the default sender with the given one. Options: alice, bob, eve, charlie",
		Destination: &argsConfig.sender,
	}

	receiver = cli.StringFlag{
		Name:        "receiver",
		Usage:       "If used, it replaces the default receiver with the given one. Options: alice, bob, eve, charlie, erd1...",
		Destination: &argsConfig.receiver,
	}

	dataField = cli.StringFlag{
		Name:        "dataField",
		Usage:       "If used, it replaces the data field with this one. Could fail in combination with some other flags, e.g. setGuardian",
		Destination: &argsConfig.dataField,
	}

	value = cli.StringFlag{
		Name:        "value",
		Usage:       "If set it replaces the default transaction value with this value. If might fail in combination with other flags, e.g setGuardian (which requires zero value)",
		Destination: &argsConfig.value,
	}

	gasLimit = cli.Uint64Flag{
		Name:        "gasLimit",
		Usage:       "If set it replaces the default gas limit with this value",
		Destination: &argsConfig.gasLimit,
	}

	withFunding = cli.BoolFlag{
		Name:        "withFunding",
		Usage:       "If set the default accounts will be funded with 10 egld",
		Destination: &argsConfig.withFunding,
	}

	send = cli.BoolFlag{
		Name:        "send",
		Usage:       "If set the transactions generated will be sent, otherwise the transactions will be just printed in JSON format",
		Destination: &argsConfig.send,
	}

	guardianSigned = cli.BoolFlag{
		Name:        "guardianSigned",
		Usage:       "If set the guardian will also sign the transaction. This works only if also guardedTxBy is set",
		Destination: &argsConfig.guardianSigned,
	}

	proxy = cli.StringFlag{
		Name:        "proxyURL",
		Usage:       "Use this to connect to mainnet, testnet or devnet. Options: mainnet, testnet, devnet or a <custom url>",
		Destination: &argsConfig.proxy,
	}

	relayedTxBy = cli.StringFlag{
		Name:        "relayedTxBy",
		Usage:       "If used, will set the relayer to the given one. Options: alice, bob, eve, charlie",
		Destination: &argsConfig.relayedTxBy,
	}

	relayerSigned = cli.BoolFlag{
		Name:        "relayerSigned",
		Usage:       "If set the relayer will also sign the transaction. This works only if also guardedTxBy is set",
		Destination: &argsConfig.relayerSigned,
	}

	argsConfig = &cfg{}
	log        = logger.GetOrCreate("mx-sdk-go/cmd/cli")
)

var homePath = os.Getenv("HOME")
var pathGeneratedWallets = homePath + "/dev/testnet-local/sandbox/node/config/walletKey.pem"
var suite = ed25519.NewEd25519()
var keyGen = signing.NewKeyGenerator(suite)

const (
	alice              = "alice"
	bob                = "bob"
	charlie            = "charlie"
	eve                = "eve"
	setGuardianGasCost = 250000
	maskGuardedTx      = 1 << 1
	mainnet            = "mainnet"
	testnet            = "testnet"
	devnet             = "devnet"
)

type cfg struct {
	withFunding    bool
	send           bool
	guardianSigned bool
	guardedTxBy    string
	guardian       string
	sender         string
	receiver       string
	dataField      string
	value          string
	gasLimit       uint64
	proxy          string
	relayerSigned  bool
	relayedTxBy    string
}

type selectedOptions struct {
	senderCryptoHolder   core.CryptoComponentsHolder
	guardianCryptoHolder core.CryptoComponentsHolder
	relayerCryptoHolder  core.CryptoComponentsHolder

	guardianAddress core.AddressHandler
	tx              transaction.FrontendTransaction
}

type testData struct {
	skFunding      []byte
	skAlice        []byte
	skBob          []byte
	skCharlie      []byte
	skEve          []byte
	addressFunding core.AddressHandler
	addressAlice   core.AddressHandler
	addressBob     core.AddressHandler
	addressCharlie core.AddressHandler
	addressEve     core.AddressHandler
}

func main() {
	_ = logger.SetLogLevel("*:DEBUG")

	app := cli.NewApp()
	cli.AppHelpTemplate = helpTemplate

	app.Name = "cli"
	app.Version = "v1.0.0"
	app.Usage = "This binary provides commands to interact with the MultiversX blockchain"

	app.Flags = []cli.Flag{
		setGuardian,
		guardedTxBy,
		sender,
		receiver,
		value,
		dataField,
		withFunding,
		gasLimit,
		send,
		guardianSigned,
		proxy,
		relayerSigned,
		relayedTxBy,
	}

	app.Action = func(_ *cli.Context) error {
		return process()
	}

	_ = app.Run(os.Args)
}

func process() error {
	td, err := loadPemFiles()
	if err != nil {
		return err
	}

	ep, err := blockchain.NewProxy(createProxyArgs())
	if err != nil {
		log.Error("error creating proxy", "error", err)
		return err
	}

	// netConfigs can be used multiple times (for example when sending multiple transactions) as to improve the
	// responsiveness of the system
	netConfigs, err := ep.GetNetworkConfig(context.Background())
	if err != nil {
		log.Error("unable to get the network configs", "error", err)
		return err
	}

	options, err := processCommand(td, ep, netConfigs)
	if err != nil {
		return err
	}

	if argsConfig.withFunding {
		err = fundWallets(td, ep, netConfigs)
		if err != nil {
			return err
		}
	}

	return generateAndSendTransaction(options, ep)
}

func processCommand(td *testData, proxy workflows.ProxyHandler, config *data.NetworkConfig) (*selectedOptions, error) {
	options, err := getDefaultOptions(td, proxy, config)
	if err != nil {
		return nil, err
	}

	err = setSenderOption(td, options)
	if err != nil {
		return nil, err
	}

	err = setReceiverOption(td, options)
	if err != nil {
		return nil, err
	}

	err = setGuardianOption(td, options)
	if err != nil {
		return nil, err
	}

	err = setGuardedTxByOption(td, options)
	if err != nil {
		return nil, err
	}

	err = setRelayedTxByOption(td, options)
	if err != nil {
		return nil, err
	}

	err = setOtherOptions(options, config)
	if err != nil {
		return nil, err
	}

	return options, nil
}

func setSenderOption(td *testData, options *selectedOptions) error {
	selectedAddress, sk, err := selectAddressAndSkFromString(td, argsConfig.sender)
	if err != nil {
		return err
	}

	if selectedAddress != nil {
		options.tx.Sender, err = selectedAddress.AddressAsBech32String()
		if err != nil {
			return err
		}

		options.senderCryptoHolder, err = cryptoProvider.NewCryptoComponentsHolder(keyGen, sk)
		if err != nil {
			return err
		}
	}

	return nil
}

func setReceiverOption(td *testData, options *selectedOptions) error {
	selectedAddress, _, err := selectAddressAndSkFromString(td, argsConfig.receiver)
	if err != nil {
		return err
	}

	if selectedAddress != nil {
		options.tx.Receiver, err = selectedAddress.AddressAsBech32String()
	}

	return err
}

func setGuardianOption(td *testData, options *selectedOptions) error {
	var err error
	selectedAddress, _, err := selectAddressAndSkFromString(td, argsConfig.guardian)
	if err != nil {
		return err
	}

	if selectedAddress != nil {
		options.guardianAddress = selectedAddress
	}
	return err
}

func setGuardedTxByOption(td *testData, options *selectedOptions) error {
	selectedAddress, sk, err := selectAddressAndSkFromString(td, argsConfig.guardedTxBy)
	if err != nil {
		return err
	}

	if selectedAddress != nil {
		options.tx.GuardianAddr, err = selectedAddress.AddressAsBech32String()
		if err != nil {
			return err
		}

		options.guardianCryptoHolder, err = cryptoProvider.NewCryptoComponentsHolder(keyGen, sk)
		if err != nil {
			return err
		}
		options.tx.Options = maskGuardedTx
	}

	return nil
}

func setRelayedTxByOption(td *testData, options *selectedOptions) error {
	selectedAddress, sk, err := selectAddressAndSkFromString(td, argsConfig.relayedTxBy)
	if err != nil {
		return err
	}

	if selectedAddress != nil {
		options.tx.RelayerAddr, err = selectedAddress.AddressAsBech32String()
		if err != nil {
			return err
		}

		options.relayerCryptoHolder, err = cryptoProvider.NewCryptoComponentsHolder(keyGen, sk)
		if err != nil {
			return err
		}
	}

	return nil
}

func selectAddressAndSkFromString(td *testData, option string) (core.AddressHandler, []byte, error) {
	var selectedAddress core.AddressHandler
	var sk []byte

	switch option {
	case alice:
		selectedAddress = td.addressAlice
		sk = td.skAlice
	case bob:
		selectedAddress = td.addressBob
		sk = td.skBob
	case charlie:
		selectedAddress = td.addressCharlie
		sk = td.skCharlie
	case eve:
		selectedAddress = td.addressEve
		sk = td.skEve
	default:
		var err error
		if len(option) > 0 {
			selectedAddress, err = data.NewAddressFromBech32String(option)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	return selectedAddress, sk, nil
}

func setOtherOptions(options *selectedOptions, config *data.NetworkConfig) error {
	if len(argsConfig.guardian) > 0 && len(argsConfig.dataField) > 0 {
		return errors.New("dataField and setGuardian cannot be set together")
	}

	err := treatDataIfNeeded(options, config)
	if err != nil {
		return err
	}

	if len(argsConfig.value) > 0 {
		options.tx.Value = argsConfig.value
	}

	return nil
}

func treatDataIfNeeded(options *selectedOptions, config *data.NetworkConfig) error {
	var err error
	if len(argsConfig.guardian) > 0 {
		options.tx.Data, err = createSetGuardianData(options.guardianAddress)
		if err != nil {
			return err
		}
		options.tx.GasLimit += setGuardianGasCost
		options.tx.Receiver = options.tx.Sender
	}
	if len(argsConfig.dataField) > 0 {
		options.tx.Data = []byte(argsConfig.dataField)
	}
	options.tx.Version = 2
	options.tx.GasLimit += uint64(len(options.tx.Data)) * config.GasPerDataByte
	if argsConfig.gasLimit != 0 {
		options.tx.GasLimit = argsConfig.gasLimit
	}

	return nil
}

func createSetGuardianData(guardianAddress core.AddressHandler) ([]byte, error) {
	builder := builders.NewTxDataBuilder()
	builder.Function("SetGuardian").ArgAddress(guardianAddress).ArgBytes([]byte(setGuardianUID))
	return builder.ToDataBytes()
}

func getDefaultOptions(td *testData, ep workflows.ProxyHandler, netConfigs *data.NetworkConfig) (*selectedOptions, error) {
	tx, _, err := ep.GetDefaultTransactionArguments(context.Background(), td.addressAlice, netConfigs)
	if err != nil {
		log.Error("unable to prepare the transaction creation arguments", "error", err)
		return nil, err
	}
	tx.Value = "0"
	tx.Receiver, err = td.addressBob.AddressAsBech32String()
	if err != nil {
		return nil, err
	}

	aliceCryptoHolder, _ := cryptoProvider.NewCryptoComponentsHolder(keyGen, td.skAlice)
	bobCryptoHolder, _ := cryptoProvider.NewCryptoComponentsHolder(keyGen, td.skBob)
	charlieCryptoHolder, _ := cryptoProvider.NewCryptoComponentsHolder(keyGen, td.skCharlie)

	return &selectedOptions{
		senderCryptoHolder:   aliceCryptoHolder,   // default if nothing provided
		guardianCryptoHolder: bobCryptoHolder,     // default if nothing provided
		relayerCryptoHolder:  charlieCryptoHolder, // default if nothing provided
		tx:                   tx,
		guardianAddress:      td.addressBob,
	}, nil
}

func generateAndSendTransaction(options *selectedOptions, proxy interactors.Proxy) error {
	txBuilder, err := builders.NewTxBuilder(cryptoProvider.NewSigner())
	if err != nil {
		log.Error("unable to prepare the transaction creation arguments", "error", err)
		return err
	}
	ti, err := interactors.NewTransactionInteractor(proxy, txBuilder)
	if err != nil {
		log.Error("error creating transaction interactor", "error", err)
		return err
	}

	copiedTx := options.tx
	err = ti.ApplyUserSignature(options.senderCryptoHolder, &copiedTx)
	if err != nil {
		log.Error("error signing transaction", "error", err)
		return err
	}

	argsConfig.relayerSigned = true
	if len(argsConfig.relayedTxBy) > 0 && argsConfig.relayerSigned {
		err = ti.ApplyRelayerSignature(options.relayerCryptoHolder, &copiedTx)
		if err != nil {
			log.Error("error applying relayer signature", "error", err)
			return err
		}
	}

	if len(argsConfig.guardedTxBy) > 0 && argsConfig.guardianSigned {
		err = ti.ApplyGuardianSignature(options.guardianCryptoHolder, &copiedTx)
		if err != nil {
			log.Error("error applying guardian signature", "error", err)
			return err
		}
	}

	ti.AddTransaction(&copiedTx)

	if argsConfig.send {
		hashes, errSend := ti.SendTransactionsAsBunch(context.Background(), 100)
		if errSend != nil {
			log.Error("error sending transaction", "error", errSend)
			return errSend
		}

		log.Info("transactions sent", "hashes", hashes)
	} else {
		for _, tx := range ti.PopAccumulatedTransactions() {
			txJson, _ := json.Marshal(tx)
			log.Info(string(txJson))
		}
	}

	return nil
}

func fundWallets(td *testData, proxy workflows.ProxyHandler, netConfigs *data.NetworkConfig) error {
	tx, _, err := proxy.GetDefaultTransactionArguments(context.Background(), td.addressFunding, netConfigs)
	if err != nil {
		log.Error("unable to prepare the transaction creation arguments", "error", err)
		return err
	}

	receivers := []core.AddressHandler{td.addressAlice, td.addressBob, td.addressEve, td.addressCharlie}

	err = sendFundWalletsTxs(td, proxy, tx, receivers)
	if err != nil {
		return err
	}

	return nil
}

func sendFundWalletsTxs(td *testData, proxy workflows.ProxyHandler, providedTx transaction.FrontendTransaction, receivers []core.AddressHandler) error {
	txBuilder, err := builders.NewTxBuilder(cryptoProvider.NewSigner())
	if err != nil {
		log.Error("unable to prepare the transaction creation arguments", "error", err)
		return err
	}

	tiProxy, ok := proxy.(interactors.Proxy)
	if !ok {
		err = errors.New("proxy assertion failure")
		log.Error("type assertion failed", "error", err)
		return err
	}

	ti, err := interactors.NewTransactionInteractor(tiProxy, txBuilder)
	if err != nil {
		log.Error("error creating transaction interactor", "error", err)
		return err
	}

	providedTx.Value = "10000000000000000000" // 10EGLD
	for _, addressHandler := range receivers {
		tx := providedTx // copy

		tx.Receiver, err = addressHandler.AddressAsBech32String()
		if err != nil {
			return err
		}

		fundingWalletCryptoHolder, localErr := cryptoProvider.NewCryptoComponentsHolder(keyGen, td.skFunding)
		if localErr != nil {
			return localErr
		}
		localErr = ti.ApplyUserSignature(fundingWalletCryptoHolder, &tx)
		if localErr != nil {
			log.Error("error signing transaction", "error", localErr)
			return localErr
		}
		ti.AddTransaction(&tx)
		providedTx.Nonce++
	}

	hashes, err := ti.SendTransactionsAsBunch(context.Background(), 100)
	if err != nil {
		log.Error("error sending transactions", "error", err)
		return err
	}

	log.Info("funding transactions sent", "hashes", hashes)
	return nil
}

func loadPemFiles() (*testData, error) {
	var err error
	td := &testData{}

	w := interactors.NewWallet()

	td.skFunding, err = w.LoadPrivateKeyFromPemFile(pathGeneratedWallets)
	if err != nil {
		log.Error("unable to load funding wallet", "error", err)
		return nil, err
	}

	td.skAlice, err = w.LoadPrivateKeyFromPemData([]byte(examples.AlicePemContents))
	if err != nil {
		log.Error("unable to load alice.pem", "error", err)
		return nil, err
	}

	td.skBob, err = w.LoadPrivateKeyFromPemData([]byte(examples.BobPemContents))
	if err != nil {
		log.Error("unable to load bob.pem", "error", err)
		return nil, err
	}

	td.skCharlie, err = w.LoadPrivateKeyFromPemData([]byte(examples.CharliePemContents))
	if err != nil {
		log.Error("unable to load charlie.pem", "error", err)
		return nil, err
	}

	td.skEve, err = w.LoadPrivateKeyFromPemData([]byte(examples.EvePemContents))
	if err != nil {
		log.Error("unable to load eve.pem", "error", err)
		return nil, err
	}

	td.addressFunding, err = w.GetAddressFromPrivateKey(td.skFunding)
	if err != nil {
		log.Error("unable to load funding address from private key", "error", err)
		return nil, err
	}

	// Generate address from private key
	td.addressAlice, err = w.GetAddressFromPrivateKey(td.skAlice)
	if err != nil {
		log.Error("unable to load alice address from the private key", "error", err)
		return nil, err
	}

	// Generate address from private key
	td.addressBob, err = w.GetAddressFromPrivateKey(td.skBob)
	if err != nil {
		log.Error("unable to load bob address from the private key", "error", err)
		return nil, err
	}

	// Generate address from private key
	td.addressCharlie, err = w.GetAddressFromPrivateKey(td.skCharlie)
	if err != nil {
		log.Error("unable to load charlie address from the private key", "error", err)
		return nil, err
	}

	// Generate address from private key
	td.addressEve, err = w.GetAddressFromPrivateKey(td.skEve)
	if err != nil {
		log.Error("unable to load eve address from the private key", "error", err)
		return nil, err
	}

	return td, nil
}

func createProxyArgs() blockchain.ArgsProxy {
	proxyURL := examples.TestnetGateway
	switch argsConfig.proxy {
	case mainnet:
		proxyURL = examples.MainnetGateway
	case testnet:
		proxyURL = examples.TestnetGateway
	case devnet:
		proxyURL = examples.DevnetGateway
	default:
		if len(argsConfig.proxy) > 0 {
			proxyURL = argsConfig.proxy
		}
	}

	return blockchain.ArgsProxy{
		ProxyURL:            proxyURL,
		Client:              nil,
		SameScState:         false,
		ShouldBeSynced:      false,
		FinalityCheck:       false,
		CacheExpirationTime: time.Minute,
		EntityType:          core.Proxy,
	}
}
