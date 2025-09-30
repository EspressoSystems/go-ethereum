package rawdb

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

var BlockSignaturePrefix = []byte("blockSignature")

func uint64ToKey(x uint64) []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, x)
	return data
}

func dbKey(prefix []byte, pos uint64) []byte {
	var key []byte
	key = append(key, prefix...)
	key = append(key, uint64ToKey(pos)...)
	return key
}

func GetBlockSignature(db ethdb.Reader, blockNumber uint64) ([]byte, error) {
	key := dbKey(BlockSignaturePrefix, (blockNumber))
	return db.Get(key)
}

func GetHashOverInterface(data interface{}) ([]byte, error) {

	dataBytes, err := rlp.EncodeToBytes(data)
	if err != nil {
		return nil, err
	}
	hash := crypto.Keccak256Hash(dataBytes)
	return hash.Bytes(), nil
}

func VerifyBlockSignature(db ethdb.Reader, number uint64, blockHash common.Hash) error {
	block := ReadBlock(db, blockHash, number)
	if block == nil {
		return fmt.Errorf("unable to get block")
	}
	return VerifySignature(db, block)
}

func VerifySignature(db ethdb.Reader, block *types.Block) error {

	blockSignature, err := GetBlockSignature(db, block.NumberU64())
	if err != nil {
		return fmt.Errorf("unable to get block signature")
	}

	hash := block.Header().Hash()

	publicKeyBytes, err := crypto.Ecrecover(hash.Bytes(), blockSignature)
	if err != nil {
		return fmt.Errorf("unable to recover public key")
	}
	pubKey, err := crypto.UnmarshalPubkey(publicKeyBytes)
	if err != nil || pubKey == nil {
		return fmt.Errorf("invalid public key")
	}
	// Public Key to address
	publicKeyAddress := crypto.PubkeyToAddress(*pubKey)
	// TODO: In follow up PRs, we should allows any valid PCR0 address registered in the contract
	// to be able to decrypt the snapshot
	snapshotAddressString := os.Getenv("SNAPSHOT_ADDRESS")
	snapshotAddress := common.HexToAddress(snapshotAddressString)

	if publicKeyAddress != snapshotAddress {
		return fmt.Errorf("invalid snapshot address")
	}
	return nil
}
