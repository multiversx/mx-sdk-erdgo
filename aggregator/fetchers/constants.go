package fetchers

const (
	// QuoteUSDFiat is the USD string
	QuoteUSDFiat = "USD"

	// QuoteUSDT is the USDT string
	QuoteUSDT = "USDT"

	// Fetchers names
	binanceName   = "Binance"
	bitfinexName  = "Bitfinex"
	cryptocomName = "Crypto.com"
	geminiName    = "Gemini"
	hitbtcName    = "HitBTC"
	huobiName     = "Huobi"
	krakenName    = "Kraken"
	okexName      = "Okex"
)

var knownFetchers = []string{binanceName, bitfinexName, cryptocomName, geminiName, hitbtcName, huobiName, krakenName, okexName}