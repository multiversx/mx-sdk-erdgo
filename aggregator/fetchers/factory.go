package fetchers

import (
	"fmt"

	"github.com/ElrondNetwork/elrond-sdk-erdgo/aggregator"
)

// MaiarTokensPair defines a base-quote pair of ids used by maiar exchange
type MaiarTokensPair struct {
	Base  string
	Quote string
}

// NewPriceFetcher returns a new price fetcher of the type provided
func NewPriceFetcher(fetcherName string, responseGetter aggregator.ResponseGetter, maiarTokensMap map[string]MaiarTokensPair) (aggregator.PriceFetcher, error) {
	if responseGetter == nil {
		return nil, errNilResponseGetter
	}
	if maiarTokensMap == nil && fetcherName == MaiarName {
		return nil, errNilMaiarTokensMap
	}

	return createFetcher(fetcherName, responseGetter, maiarTokensMap)
}

func createFetcher(fetcherName string, responseGetter aggregator.ResponseGetter, maiarTokensMap map[string]MaiarTokensPair) (aggregator.PriceFetcher, error) {
	switch fetcherName {
	case BinanceName:
		return &binance{
			ResponseGetter: responseGetter,
			baseFetcher:    baseFetcher{},
		}, nil
	case BitfinexName:
		return &bitfinex{
			ResponseGetter: responseGetter,
			baseFetcher:    baseFetcher{},
		}, nil
	case CryptocomName:
		return &cryptocom{
			ResponseGetter: responseGetter,
			baseFetcher:    baseFetcher{},
		}, nil
	case GeminiName:
		return &gemini{
			ResponseGetter: responseGetter,
			baseFetcher:    baseFetcher{},
		}, nil
	case HitbtcName:
		return &hitbtc{
			ResponseGetter: responseGetter,
			baseFetcher:    baseFetcher{},
		}, nil
	case HuobiName:
		return &huobi{
			ResponseGetter: responseGetter,
			baseFetcher:    baseFetcher{},
		}, nil
	case KrakenName:
		return &kraken{
			ResponseGetter: responseGetter,
			baseFetcher:    baseFetcher{},
		}, nil
	case OkexName:
		return &okex{
			ResponseGetter: responseGetter,
			baseFetcher:    baseFetcher{},
		}, nil
	case MaiarName:
		return &maiar{
			ResponseGetter: responseGetter,
			baseFetcher:    baseFetcher{},
			maiarTokensMap: maiarTokensMap,
		}, nil
	}
	return nil, fmt.Errorf("%w, fetcherName %s", errInvalidFetcherName, fetcherName)
}
