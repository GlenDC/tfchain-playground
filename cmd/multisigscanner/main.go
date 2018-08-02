package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/bgentry/speakeasy"
	"github.com/rivine/rivine/api"
	"github.com/rivine/rivine/crypto"
	"github.com/rivine/rivine/modules"
	"github.com/rivine/rivine/types"
)

const (
	initialKeys = 2025 // based on the original key size limitations of rivine
	keyHop      = 1024
	maxKeys     = 100e6
)

func main() {
	mnemonic, err := speakeasy.Ask("Seed Mnemonic: ")
	onError(err)
	seed, err := modules.InitialSeedFromMnemonic(mnemonic)
	onError(err)

	// dedup multisig addresses
	multisigaddresses := make(map[types.UnlockHash]struct{}, initialKeys)

	// start timer
	start := time.Now()

	tn := runtime.NumCPU() * 2
	keyCh := make(chan unlockHashIndexPair, tn*8)
	ch := make(chan scanResult, tn*8)

	log.Println("scanning keys for multisig addresses using https://explorer.testnet.threefoldtoken.com...")
	// scan all spendable keys
	for cpu := 0; cpu < tn; cpu++ {
		go func(chanIndex uint64) {
			for pair := range keyCh {
				resp, err := http.Get("https://explorer.testnet.threefoldtoken.com/explorer/hashes/" + pair.UnlockHash.String())
				if onError(err) {
					ch <- scanResult{}
					return
				}
				if resp.StatusCode != 200 {
					if resp.StatusCode != 400 {
						msg, _ := ioutil.ReadAll(resp.Body)
						resp.Body.Close()
						onError(fmt.Errorf("unexpected status code %d: %v", resp.StatusCode, msg))
						ch <- scanResult{}
						return
					}
					log.Println("ignorning uh (" + strconv.FormatUint(pair.Index, 10) + ") " +
						pair.UnlockHash.String() + " as we received status code " + strconv.Itoa(resp.StatusCode))
					ch <- scanResult{MultiSigAddresses: nil, UnlockHashFound: false}
					continue
				}
				decoder := json.NewDecoder(resp.Body)
				var explorerHashGet api.ExplorerHashGET
				err = decoder.Decode(&explorerHashGet)
				resp.Body.Close()
				if onError(err) {
					ch <- scanResult{MultiSigAddresses: nil, UnlockHashFound: false}
					return
				}
				mn := len(explorerHashGet.MultiSigAddresses)
				if mn == 0 {
					log.Println("uh (" + strconv.FormatUint(pair.Index, 10) + ") " +
						pair.UnlockHash.String() + " is not part of any multisig wallet")
					ch <- scanResult{MultiSigAddresses: nil, UnlockHashFound: true}
					continue
				}
				log.Println("uh (" + strconv.FormatUint(pair.Index, 10) + ") " +
					pair.UnlockHash.String() + " is part of " + strconv.Itoa(mn) + " multisig wallets: {" +
					unlockHashSliceAsString(explorerHashGet.MultiSigAddresses) + "}")
				ch <- scanResult{MultiSigAddresses: explorerHashGet.MultiSigAddresses, UnlockHashFound: true}
			}
			ch <- scanResult{ChannelCloseIndex: chanIndex + 1}
		}(uint64(cpu))
	}

	keys := generateKeys(seed, 0, initialKeys)
	ki := uint64(0)
	fki := uint64(0)
	foundKeys := false

	// scan keys and gather results
	for {
		// check our key index, and expand key range if needed
		if length := uint64(len(keys)); ki == length {
			// first ensure that all our results are coming in,
			// for the already requested keys
			for fki < ki {
				result := <-ch
				fki++
				foundKeys = foundKeys || result.UnlockHashFound
				for _, uh := range result.MultiSigAddresses {
					multisigaddresses[uh] = struct{}{}
				}
			}

			// check foundKeys & ki
			if !foundKeys {
				// no keys were found, we can stop
				break
			}
			if ki == maxKeys {
				// stop the scanning with a panic
				panic("reached maximum amount of keys, and still scanning")
			}
			// generate more keys
			newLength := length + keyHop
			if newLength > maxKeys {
				// clamp to max keys
				newLength = maxKeys
			}
			keys = append(keys, generateKeys(seed, ki, newLength-length)...)
			foundKeys = false
		}

		select {
		case keyCh <- unlockHashIndexPair{UnlockHash: keys[ki].UnlockHash(), Index: ki}:
			log.Printf("send key %d/%d to scan (max keys: %d)...", ki, len(keys), uint64(maxKeys))
			// send more keys to scan
			ki++
		case result := <-ch:
			fki++
			foundKeys = foundKeys || result.UnlockHashFound
			// collecting incoming multisig addresses
			for _, uh := range result.MultiSigAddresses {
				multisigaddresses[uh] = struct{}{}
			}
		}
	}

	// close keyCh
	close(keyCh)

	// collect the still incoming multisig addresses
	dn := tn
	for result := range ch {
		if result.ChannelCloseIndex > 0 {
			log.Printf("scan channel %d/%d closed", result.ChannelCloseIndex, tn)
			// check our special uh slice, as it is used to identify a finished goroutine
			dn--
			if dn == 0 {
				close(ch)
				break
			}
			continue
		}
		for _, uh := range result.MultiSigAddresses {
			multisigaddresses[uh] = struct{}{}
		}
	}

	// stop timer and report time
	duration := time.Now().Sub(start)
	fmt.Println("found " + strconv.Itoa(len(multisigaddresses)) + " multisig address(es)")
	fmt.Println(unlockHashMapAsString(multisigaddresses))
	fmt.Println("time it took to scan " + strconv.FormatUint(fki, 10) + " keys of given seed: " + duration.String())
}

type unlockHashIndexPair struct {
	UnlockHash types.UnlockHash
	Index      uint64
}
type scanResult struct {
	MultiSigAddresses []types.UnlockHash
	UnlockHashFound   bool
	ChannelCloseIndex uint64
}
type spendableKey struct {
	PublicKey crypto.PublicKey
	SecretKey crypto.SecretKey
}

func (sk spendableKey) UnlockHash() types.UnlockHash {
	return types.NewEd25519PubKeyUnlockHash(sk.PublicKey)
}

func unlockHashSliceAsString(uhs []types.UnlockHash) (s string) {
	for _, uh := range uhs {
		s += " " + uh.String()
	}
	return s[1:]
}

func unlockHashMapAsString(uhs map[types.UnlockHash]struct{}) (s string) {
	for uh := range uhs {
		s += " " + uh.String()
	}
	return s[1:]
}

func generateKeys(seed modules.Seed, start, n uint64) []spendableKey {
	// generate in parallel, one goroutine per core.
	keys := make([]spendableKey, n)
	var wg sync.WaitGroup
	wg.Add(runtime.NumCPU())
	for cpu := 0; cpu < runtime.NumCPU(); cpu++ {
		go func(offset uint64) {
			defer wg.Done()
			for i := offset; i < n; i += uint64(runtime.NumCPU()) {
				// NOTE: don't bother trying to optimize generateSpendableKey;
				// profiling shows that ed25519 key generation consumes far
				// more CPU time than encoding or hashing.
				keys[i] = generateSpendableKey(seed, start+i)
			}
		}(uint64(cpu))
	}
	wg.Wait()
	return keys
}
func generateSpendableKey(seed modules.Seed, index uint64) spendableKey {
	sk, pk := crypto.GenerateKeyPairDeterministic(crypto.HashAll(seed, index))
	return spendableKey{
		PublicKey: pk,
		SecretKey: sk,
	}
}

func onError(err error) bool {
	if err == nil {
		return false
	}
	fmt.Fprintln(os.Stderr, "error: "+err.Error())
	os.Exit(1)
	return true
}
