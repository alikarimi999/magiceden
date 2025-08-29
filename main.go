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
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"golang.org/x/term"
)

var (
	magicUrl     = "https://api-mainnet.magiceden.io/v4/self_serve/nft/mint_token"
	rpc0         = "https://rpc.ankr.com/monad_testnet"
	rpc1         = "https://monad-testnet.drpc.org"
	rpc2         = "https://testnet-rpc.monad.xyz"
	rpc3         = "https://monad-testnet.gateway.tatum.io"
	rpcs         = []string{rpc0, rpc1, rpc2, rpc3}
	collectionId = ""
)

type Chain string

const (
	monad Chain = "monad-testnet"
)

type Kind string

const (
	AllowList Kind = "allowlist"
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
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return err
	}
	publicKey := privateKey.Public().(*ecdsa.PublicKey)
	fromAddr := crypto.PubkeyToAddress(*publicKey)

	payload := map[string]interface{}{
		"chain":        chain,
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

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), privateKey)
	if err != nil {
		return err
	}

	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		return err
	}

	fmt.Printf("✅ Mint transaction sent! Hash: %s\n", signedTx.Hash().Hex())
	return nil
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

	var wg sync.WaitGroup

	for _, key := range privateKeys {
		wg.Add(1)
		go func(pk string) {
			defer wg.Done()
			pk = strings.TrimSpace(pk)
			if err := MintNFT(client, pk, collectionId, ERC1155, AllowList, monad,
				0, chainId); err != nil {
				log.Println("Error minting for", pk[:10]+"...", err)
			}
		}(key)
	}

	wg.Wait()
	fmt.Println("All minting tasks finished.")

}
