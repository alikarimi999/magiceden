package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/term"
)

var (
	magicUrl = "https://api-mainnet.magiceden.io/v4/self_serve/nft/mint_token"
	rpc0     = "https://rpc.ankr.com/monad_testnet"
	rpc1     = "https://monad-testnet.drpc.org"
	rpc2     = "https://testnet-rpc.monad.xyz"
	rpc3     = "https://monad-testnet.gateway.tatum.io"
	rpcs     = []string{rpc0, rpc1, rpc2, rpc3}

	// set these
	collectionId = "0xae52ca8e359f8ade8c0642dbc28f9fc4d1354a90" // set your collection ID here
	protocol     = ERC1155
	kind         = Public
	publicRepeat = 10
	target       = time.Date(2025, 9, 26, 15, 46, 8, 0, time.Local) // set your target date here

)

type Chain string

const (
	monad Chain = "monad-testnet"
)

type Kind string

const (
	AllowList Kind = "allowlist"
	Public    Kind = "public"
)

type Protocol string

const (
	ERC1155 Protocol = "ERC1155"
)

type MintStep struct {
	ID     string `json:"id"`
	Chain  string `json:"chain"`
	Method string `json:"method"`
	Params struct {
		From  string `json:"from"`
		To    string `json:"to"`
		Value string `json:"value"`
		Data  string `json:"data"`
	} `json:"params"`
}

type MintResponse struct {
	Steps []MintStep `json:"steps"`
}

// MintNFT calls Magic Eden API and executes the mint transaction
func MintNFT(client *ethclient.Client, privateKeyHex, collectionId string, protocol Protocol, kind Kind,
	chain Chain, tokenId int, chainId *big.Int) error {
	// 4. Load private key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	fromAddr := crypto.PubkeyToAddress(*publicKey)

	// 1. Build API request payload
	payload := map[string]interface{}{
		"chain":        chain, // or "monad-testnet" if fixed
		"collectionId": collectionId,
		"wallet": map[string]string{
			"address": fromAddr.String(),
			"chain":   string(chain),
		},
		"nftAmount": 1,
		"kind":      kind,
		"protocol":  protocol,
		"tokenId":   tokenId,
	}
	body, _ := json.Marshal(payload)

	// 2. Call Magic Eden Launchpad API
	req, err := http.NewRequest("POST", magicUrl, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	// log.Println("API Response:", string(respBody))

	var mintResp MintResponse
	if err := json.Unmarshal(respBody, &mintResp); err != nil {
		return err
	}
	if len(mintResp.Steps) == 0 {
		return fmt.Errorf("no steps returned from API")
	}

	step := mintResp.Steps[0]

	// 5. Build transaction
	nonce, err := client.PendingNonceAt(context.Background(), fromAddr)
	if err != nil {
		return err
	}

	value := new(big.Int)
	value.SetString(step.Params.Value, 10)

	gasLimit := uint64(500000) // tune if needed
	// gasLimit, err := client.EstimateGas(context.Background(), msg)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		return err
	}

	toAddr := common.HexToAddress(step.Params.To)
	data := common.FromHex(step.Params.Data)

	tx := types.NewTransaction(nonce, toAddr, value, gasLimit, gasPrice, data)

	// 6. Sign transaction
	// pass the chainId to the function for a faster operation
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), privateKey)
	if err != nil {
		return err
	}

	// 7. Send transaction
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return err
	}

	fmt.Printf("✅ Mint transaction sent! Hash: %s\n", signedTx.Hash().Hex())
	return nil
}

func counter(target time.Time) {
	for {
		remaining := time.Until(target)
		if remaining <= 0 {
			break
		}
		h := int(remaining.Hours())
		m := int(remaining.Minutes()) % 60
		s := int(remaining.Seconds()) % 60
		fmt.Printf("\rCountdown: %02d:%02d:%02d", h, m, s)
		time.Sleep(1 * time.Second)
	}
	fmt.Println("\nTime's up! Starting minting process...")
}

func main() {

	var client *ethclient.Client
	var chainId *big.Int
	var err error
	for _, rpc := range rpcs {
		client, err = ethclient.Dial(rpc)
		if err != nil {
			continue
		}

		chainId, err = client.NetworkID(context.Background())
		if err != nil {
			continue
		}
		break
	}

	fmt.Print("Enter your private keys (comma separated): ")
	byteKey, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println() // newline after input

	input := string(byteKey)
	privateKeys := strings.Split(input, ",")

	// print imported addresses
	for i, pk := range privateKeys {
		pk = strings.TrimSpace(pk)
		privateKey, err := crypto.HexToECDSA(pk)
		if err != nil {
			log.Println("Error importing private key:", err)
			return
		}
		address := crypto.PubkeyToAddress(privateKey.PublicKey)
		fmt.Printf("address-%d: %s\n", i, address.Hex())
	}

	now := time.Now()
	// If the target time passed, start immediately
	// If the target time is in the future, wait until that time
	if target.After(now) {
		go counter(target)
		duration := time.Until(target)

		timer := time.NewTimer(duration)
		<-timer.C
	}

	for _, key := range privateKeys {
		go func(pk string) {
			pk = strings.TrimSpace(pk)

			privateKey, _ := crypto.HexToECDSA(pk)
			address := crypto.PubkeyToAddress(privateKey.PublicKey)
			// Determine the number of times to repeat the minting process
			repeat := 1
			if kind == Public {
				repeat = publicRepeat
			}
			for i := 0; i < repeat; i++ {
				go func() {
					fmt.Println("Try Mint: ", address, " - ", i)
					if err := MintNFT(client, pk, collectionId, protocol, kind, monad,
						0, chainId); err != nil {
						log.Println("Error minting for", address.Hex()+"...", err)
					}
				}()
				time.Sleep(time.Duration(i+2) * time.Nanosecond)
			}

		}(key)
	}

	select {}
}
