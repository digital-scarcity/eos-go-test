package eostest

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/dfuse-io/logging"
	"github.com/eoscanada/eos-go"
	"github.com/eoscanada/eos-go/ecc"
	"github.com/eoscanada/eos-go/system"
	"github.com/k0kubun/go-ansi"
	"github.com/schollz/progressbar/v3"

	"go.uber.org/zap"
)

const charset = "abcdefghijklmnopqrstuvwxyz" + "12345"
const creator = "eosio"
const retries = 10
const retrySleep = 2

type ProgressBarInterface interface {
	Add(int) error
	Clear() error
	RenderBlank() error
	Reset()
	Finish() error
	Set(int) error
	IsFinished() bool
}

var cmd *exec.Cmd = nil
var zlog *zap.Logger

func init() {
	logging.Register("github.com/digital-scarcity/eos-go-test", &zlog)
}

type FakeProgressBar struct {
}

func (r *FakeProgressBar) Add(int) error {
	return nil
}

func (r *FakeProgressBar) Clear() error {
	return nil
}

func (r *FakeProgressBar) RenderBlank() error {
	return nil
}

func (r *FakeProgressBar) Reset() {
}

func (r *FakeProgressBar) Finish() error {
	return nil
}

func (r *FakeProgressBar) Set(int) error {
	return nil
}

func (r *FakeProgressBar) IsFinished() bool {
	return true
}

func (r *FakeProgressBar) render() error {
	return nil
}

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func IsInteractive() bool {
	return os.Getenv("INTERACTIVE_MODE") != "false"
}

func stringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandAccountName() string {
	return stringWithCharset(12, charset)
}

// DefaultKey returns the default EOSIO key
func DefaultKey() string {
	return "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
}

func ExecWithRetry(ctx context.Context, api *eos.API, actions []*eos.Action) (string, error) {
	return Trx(ctx, api, actions, retries)
}

func isRetryableError(err error) bool {
	errMsg := err.Error()
	// fmt.Println("Error: ", errMsg)
	return strings.Contains(errMsg, "deadline") ||
		strings.Contains(errMsg, "connection reset by peer") ||
		strings.Contains(errMsg, "Transaction took too long") ||
		strings.Contains(errMsg, "exceeded the current CPU usage limit") ||
		strings.Contains(errMsg, "ABI serialization time has exceeded")

}

// ExecTrx executes a list of actions
func ExecTrx(ctx context.Context, api *eos.API, actions []*eos.Action) (string, error) {
	txOpts := &eos.TxOptions{}
	if err := txOpts.FillFromChain(ctx, api); err != nil {
		return "error", fmt.Errorf("error filling tx opts: %s", err)
	}

	tx := eos.NewTransaction(actions, txOpts)

	_, packedTx, err := api.SignTransaction(ctx, tx, txOpts.ChainID, eos.CompressionNone)
	if err != nil {
		return "error", fmt.Errorf("error signing transaction: %s", err)
	}

	response, err := api.PushTransaction(ctx, packedTx)
	if err != nil {
		return "error", fmt.Errorf("error pushing transaction: %s", err)
	}
	trxID := hex.EncodeToString(response.Processed.ID)
	return trxID, nil
}

func Trx(ctx context.Context, api *eos.API, actions []*eos.Action, retries int) (string, error) {
	response, err := ExecTrx(ctx, api, actions)
	if err != nil {
		if retries > 0 {
			// fmt.Println("Attempt: ", retries)
			if isRetryableError(err) {
				time.Sleep(time.Duration(retrySleep) * time.Second)
				return Trx(ctx, api, actions, retries-1)
			}
		}
		return "", err
	}
	return response, nil
}

// CreateAccount creates an account and sets the eosio.code permission on active
func CreateAccount(ctx context.Context, api *eos.API, accountName string, publicKey ecc.PublicKey) (eos.AccountName, error) {
	acct := eos.AN(accountName)

	actions := []*eos.Action{system.NewNewAccount(creator, acct, publicKey)}
	_, err := ExecTrx(ctx, api, actions)
	if err != nil {
		return eos.AccountName(""), fmt.Errorf("error filling tx opts: %s", err)
	}

	codePermissionActions := []*eos.Action{system.NewUpdateAuth(acct,
		"active",
		"owner",
		eos.Authority{
			Threshold: 1,
			Keys: []eos.KeyWeight{{
				PublicKey: publicKey,
				Weight:    1,
			}},
			Accounts: []eos.PermissionLevelWeight{{
				Permission: eos.PermissionLevel{
					Actor:      acct,
					Permission: "eosio.code",
				},
				Weight: 1,
			}},
			Waits: []eos.WaitWeight{},
		}, "owner")}

	_, err = ExecTrx(ctx, api, codePermissionActions)
	if err != nil {
		return "", fmt.Errorf("error filling tx opts: %s", err)
	}
	return acct, nil
}

// CreateAccountWithRandomKey specifies a name and uses a random key to create account (adds to Keybag)
func CreateAccountWithRandomKey(ctx context.Context, api *eos.API, accountName string) (ecc.PublicKey, eos.AccountName, error) {

	key, _ := ecc.NewRandomPrivateKey()
	err := api.Signer.ImportPrivateKey(ctx, key.String())
	if err != nil {
		return ecc.PublicKey{}, "", fmt.Errorf("error importing key: %s", err)
	}

	acct, err := CreateAccount(ctx, api, accountName, key.PublicKey())
	return key.PublicKey(), acct, err
}

// CreateAccountWithRandomName ...
func CreateAccountWithRandomName(ctx context.Context, api *eos.API, key ecc.PublicKey) (eos.AccountName, error) {
	return CreateAccount(ctx, api, RandAccountName(), key)
}

// CreateAccountFromString creates an specific account from a string name
func CreateAccountFromString(ctx context.Context, api *eos.API, accountName, privateKey string) (eos.AccountName, error) {

	key, err := ImportKey(ctx, api, privateKey)
	if err != nil {
		return "", err
	}

	return CreateAccount(ctx, api, accountName, key.PublicKey())
}

func ImportKey(ctx context.Context, api *eos.API, privateKey string) (*ecc.PrivateKey, error) {

	key, err := ecc.NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("privateKey parameter is not a valid format: %s", err)
	}

	keys, err := api.Signer.AvailableKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting available key: %s", err)
	}
	for _, k := range keys {
		if k.String() == key.PublicKey().String() {
			return key, nil
		}
	}

	err = api.Signer.ImportPrivateKey(ctx, privateKey)
	if err != nil {
		return nil, fmt.Errorf("error importing key: %s", err)
	}
	return key, nil
}

// CreateAccountWithRandomNameAndKey ...
func CreateAccountWithRandomNameAndKey(ctx context.Context, api *eos.API) (ecc.PublicKey, eos.AccountName, error) {

	return CreateAccountWithRandomKey(ctx, api, RandAccountName())
}

// CreateRandoms returns a list of accounts with eosio.code permission attached to active
func CreateRandomAccountsDefaultKey(ctx context.Context, api *eos.API, length int) ([]eos.AccountName, error) {

	accounts := make([]eos.AccountName, length)
	i := 0
	for i < length {
		account, err := CreateAccountFromString(ctx, api, RandAccountName(), DefaultKey())
		if err != nil {
			return []eos.AccountName{}, fmt.Errorf("cannot create accounts: %s", err)
		}
		accounts[i] = account
		i++
	}
	return accounts, nil
}

// CreateRandoms returns a list of accounts with eosio.code permission attached to active
func CreateRandoms(ctx context.Context, api *eos.API, length int) ([]eos.AccountName, error) {

	accounts := make([]eos.AccountName, length)
	i := 0
	for i < length {
		_, account, err := CreateAccountWithRandomNameAndKey(ctx, api)
		if err != nil {
			return []eos.AccountName{}, fmt.Errorf("error importing key: %s", err)
		}
		accounts[i] = account
		i++
	}
	return accounts, nil
}

// SetContract sets the wasm and abi files to the account
func SetContract(ctx context.Context, api *eos.API, accountName eos.AccountName, wasmFile, abiFile string) (string, error) {
	setCodeAction, err := system.NewSetCode(accountName, wasmFile)
	if err != nil {
		return "", fmt.Errorf("unable construct set_code action: %v", err)
	}

	setAbiAction, err := system.NewSetABI(accountName, abiFile)
	if err != nil {
		return "", fmt.Errorf("unable construct set_abi action: %v", err)
	}

	resp, err := Trx(ctx, api, []*eos.Action{setCodeAction, setAbiAction}, 3)
	if err != nil {
		errMsg := err.Error()
		// fmt.Println("Error: ", errMsg)
		if !strings.Contains(errMsg, "Contract is already running this version of code") {
			return "", err
		}
	}
	return resp, nil
}

type tokenCreate struct {
	Issuer    eos.AccountName
	MaxSupply eos.Asset
}

// DeployAndCreateToken deploys the standard token contract and creates the specified token max supply
func DeployAndCreateToken(ctx context.Context, t *testing.T, api *eos.API, tokenHome string,
	contract, issuer eos.AccountName, maxSupply eos.Asset) (string, error) {

	// TODO: how to save wasm and abi to distribute with package
	_, err := SetContract(ctx, api, contract, tokenHome+"/token/token.wasm", tokenHome+"/token/token.abi")
	if err != nil {
		return "", fmt.Errorf("cannot set contract: %s", err)
	}

	actions := []*eos.Action{{
		Account: contract,
		Name:    eos.ActN("create"),
		Authorization: []eos.PermissionLevel{
			{Actor: contract, Permission: eos.PN("active")},
		},
		ActionData: eos.NewActionData(tokenCreate{
			Issuer:    issuer,
			MaxSupply: maxSupply,
		}),
	}}

	t.Log("Created Token : ", contract, " 		: ", maxSupply.String())
	return ExecTrx(ctx, api, actions)
}

// Pause will pause execution and print a head
func Pause(seconds time.Duration, headline, prefix string) {
	if headline != "" {
		zlog.Info("Pausing for", zap.Duration("duration", seconds), zap.String("headline", headline))
	}

	bar := DefaultProgressBar(prefix, 100)

	chunk := seconds / 100
	for i := 0; i < 100; i++ {
		err := bar.Add(1)
		if err != nil {
			zlog.Error("Cannot increment progress bar", zap.Error(err))
		}

		time.Sleep(chunk)
	}
}

func DefaultProgressBar(prefix string, counter int) ProgressBarInterface {

	if !IsInteractive() {
		return &FakeProgressBar{}
	}

	return progressbar.NewOptions(counter,
		progressbar.OptionSetWriter(ansi.NewAnsiStdout()),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionSetWidth(90),
		// progressbar.OptionShowIts(),
		progressbar.OptionSetDescription("[cyan]"+fmt.Sprintf("%20v", prefix)),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}))
}

func RestartNodeos(useDefault bool, arg ...string) (*exec.Cmd, error) {
	if cmd != nil {
		err := cmd.Process.Signal(os.Interrupt)
		if err != nil {
			fmt.Println("error killing process, err:", err)
		}
		procState, err := cmd.Process.Wait()
		if err != nil {
			fmt.Println("error waiting process, err:", err)
		}

		if !procState.Exited() {
			// panic(fmt.Sprintf("Nodeos process, failed to exit correctly, exit code: %v", procState.ExitCode()))
			panic("Nodeos process did not exit")
		}
		// time.Sleep(time.Second * 2)
	} else {
		// cancel nodeos if it is running
		_, err := exec.Command("sh", "-c", "pkill -SIGINT nodeos").Output()
		if err == nil {
			Pause(time.Second, "Killing nodeos ...", "")
		}
	}

	// start nodeos with some reasonable defaults
	if useDefault {
		cmd = exec.Command("nodeos", "-e", "-p", "eosio",
			"--plugin", "eosio::producer_plugin",
			"--plugin", "eosio::producer_api_plugin",
			"--plugin", "eosio::chain_api_plugin",
			"--plugin", "eosio::http_plugin",
			"--access-control-allow-origin", "*",
			"--contracts-console",
			"--http-validate-host", "false",
			"--verbose-http-errors",
			"--delete-all-blocks")
	} else {
		cmd = exec.Command("nodeos", arg...)
	}

	// outfile, err := os.Create("./nodeos-go.log")
	// if err != nil {
	// 	return nil, fmt.Errorf("unable to create nodeos-go.log file: %v", err)
	// }

	// defer outfile.Close()
	// cmd.Stdout = outfile
	// cmd.Stderr = outfile

	err := cmd.Start()
	if err != nil {
		return nil, err
	}

	Pause(time.Second, "", "")
	return cmd, nil
}
