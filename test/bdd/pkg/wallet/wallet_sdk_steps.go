package wallet

import (
	"fmt"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"

	"github.com/hyperledger/aries-framework-go/pkg/wallet"

	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

// WalletSDKSteps contains steps for wallet tests using Go SDK bindings.
type WalletSDKSteps struct {
	context *context.BDDContext
	wallets map[string]*wallet.Wallet
	tokens  map[string]string
}

// NewWalletSDKSteps returns a WalletSDKSteps instance.
func NewWalletSDKSteps() *WalletSDKSteps {
	return &WalletSDKSteps{
		wallets: map[string]*wallet.Wallet{},
		tokens:  map[string]string{},
	}
}

// SetContext is called before every scenario is run with a fresh context.
func (w *WalletSDKSteps) SetContext(ctx *context.BDDContext) {
	w.context = ctx
	w.wallets = map[string]*wallet.Wallet{}
	w.tokens = map[string]string{}
}

// RegisterSteps registers the BDD test steps on the suite.
func (w *WalletSDKSteps) RegisterSteps(suite *godog.Suite) {
}

const defaultPassphrase = "password123"

func (w *WalletSDKSteps) CreateWallet(agent string) error {
	agentCtx, ok := w.context.AgentCtx[agent]
	if !ok {
		return fmt.Errorf("no context initialized for agent '%s'", agent)
	}

	err := wallet.CreateProfile(agent, agentCtx,
		wallet.WithPassphrase(defaultPassphrase),
		wallet.WithSecretLockService(&noop.NoLock{}))
	if err != nil {
		return err
	}

	agentWallet, err := wallet.New(agent, agentCtx)
	if err != nil {
		return err
	}

	w.wallets[agent] = agentWallet
	return nil
}

func (w *WalletSDKSteps) UnlockWallet(agent string) error {
	agentWallet, ok := w.wallets[agent]
	if !ok {
		return fmt.Errorf("wallet not created yet for agent '%s'", agent)
	}

	tok, err := agentWallet.Open(wallet.WithUnlockByPassphrase(defaultPassphrase))
	if err != nil {
		return err
	}

	w.tokens[agent] = tok
	return nil
}

/*
TODO steps:
 - unlock wallet
 - receive issued credential
 - create presentation
 - verify presentation
*/
