package eostest_test

import (
	"context"
	"testing"
	"time"

	eostest "github.com/digital-scarcity/eos-go-test"
	"github.com/eoscanada/eos-go"
	"github.com/eoscanada/eos-go/ecc"
	"github.com/stretchr/testify/require"
	"gotest.tools/assert"
)

const testingEndpoint = "http://localhost:8888"
const defaultKey = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"

var chainResponsePause time.Duration

func setupTestCase(t *testing.T) func(t *testing.T) {
	t.Log("Bootstrapping testing environment ...")

	cmd, err := eostest.RestartNodeos(true)
	assert.NilError(t, err)

	chainResponsePause = time.Second
	t.Log("nodeos PID: ", cmd.Process.Pid)

	return func(t *testing.T) {
		// any cleanup code would go here
	}
}

func TestNewRandomPrivateKey(t *testing.T) {
	key, err := ecc.NewRandomPrivateKey()
	require.NoError(t, err)
	assert.Assert(t, key.String() != "")
}

func TestK1PrivateToPublic(t *testing.T) {
	wif := "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss"
	privKey, err := ecc.NewPrivateKey(wif)
	require.NoError(t, err)

	pubKey := privKey.PublicKey()

	pubKeyString := pubKey.String()
	assert.Equal(t, "EOS859gxfnXyUriMgUeThh1fWv3oqcpLFyHa3TfFYC4PK2HqhToVM", pubKeyString)
}

func TestCreateAccountWithKey(t *testing.T) {

	teardownTestCase := setupTestCase(t)
	defer teardownTestCase(t)

	ctx := context.Background()
	api := eos.New(testingEndpoint)
	keyBag := &eos.KeyBag{}
	api.SetSigner(keyBag)
	err := keyBag.ImportPrivateKey(ctx, defaultKey)
	assert.NilError(t, err)

	randomAccountName := eostest.RandAccountName()
	account, err := eostest.CreateAccountFromString(ctx, api, randomAccountName, "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3")
	assert.NilError(t, err)
	t.Log("Creating account: ", randomAccountName)

	assert.Equal(t, string(account), randomAccountName)
}

func TestCreateAccountWithRandomKey(t *testing.T) {

	teardownTestCase := setupTestCase(t)
	defer teardownTestCase(t)

	ctx := context.Background()
	api := eos.New(testingEndpoint)
	keyBag := &eos.KeyBag{}
	err := keyBag.ImportPrivateKey(ctx, defaultKey)
	assert.NilError(t, err)
	api.SetSigner(keyBag)

	randomAccountName := eostest.RandAccountName()
	key, account, err := eostest.CreateAccountWithRandomKey(ctx, api, randomAccountName)
	assert.NilError(t, err)

	t.Log("New random key: ", key.String())
	t.Log("Created account: ", randomAccountName, " with random key")

	assert.Equal(t, string(account), randomAccountName)
}

func TestCreateAccountWithRandomNameAndKey(t *testing.T) {

	teardownTestCase := setupTestCase(t)
	defer teardownTestCase(t)

	ctx := context.Background()
	api := eos.New(testingEndpoint)
	keyBag := &eos.KeyBag{}
	err := keyBag.ImportPrivateKey(ctx, defaultKey)
	assert.NilError(t, err)
	api.SetSigner(keyBag)

	key, account, err := eostest.CreateAccountWithRandomNameAndKey(ctx, api)
	assert.NilError(t, err)

	t.Log("New random key: ", key.String())
	t.Log("Created account: ", string(account))
}
