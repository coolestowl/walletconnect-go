package walletconnectgo

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"runtime"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/websocket"
	"github.com/panjf2000/ants/v2"
	"github.com/samber/lo"
	"golang.org/x/net/proxy"
)

type Core struct {
	RpcHub

	subRecvChan chan json.RawMessage
	topicSubs   map[string]chan json.RawMessage

	pool       *ants.Pool
	socksProxy string
	km         keyManager
	ProjectId  string
}

func (c *Core) SetProxy(socksProxy string) {
	c.socksProxy = socksProxy
}

func (c *Core) dial(urlStr string, requestHeader http.Header) error {
	d := &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	if c.socksProxy != "" {
		dialer, err := proxy.SOCKS5("tcp", c.socksProxy, nil, proxy.Direct)
		if err != nil {
			return err
		}
		d.NetDial = dialer.Dial
	}

	wsConn, httpResp, err := d.Dial(urlStr, requestHeader)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	c.RpcHub = WithWebsocket(wsConn)
	c.pool = lo.Must(ants.NewPool(runtime.NumCPU()))
	c.topicSubs = make(map[string]chan json.RawMessage)
	c.subRecvChan = make(chan json.RawMessage)
	go c.subscriptionDispatcher()
	return nil
}

func (c *Core) subscriptionDispatcher() {
	for msg := range c.subRecvChan {
		c.pool.Submit(func() {
			var rpc IRNSubscription
			if err := json.Unmarshal(msg, &rpc); err != nil {
				slog.Error("[Core] unmarshal failed", "err", err)
				return
			}

			ch, ok := c.topicSubs[rpc.Topic]
			if !ok {
				slog.Error("[Core] no subscriber found for topic", "topic", rpc.Topic)
				return
			}

			topicKey, ok := c.km.Get(rpc.Topic)
			if !ok {
				slog.Error("[Core] no key found for topic", "topic", rpc.Topic)
				return
			}

			encryptedMsg, err := base64.StdEncoding.DecodeString(rpc.Message)
			if err != nil {
				slog.Error("[Core] base64 decode failed", "err", err)
				return
			}

			decryptedMsg, err := chacha20poly1305Decrypt(encryptedMsg[1:], topicKey)
			if err != nil {
				slog.Error("[Core] decrypt failed", "err", err)
				return
			}

			ch <- json.RawMessage(decryptedMsg)
		})
	}
}

func (c *Core) sendRequest(topic, method string, params any) (json.RawMessage, error) {
	r, err := newJSONRPCReq(method, params)
	if err != nil {
		return nil, err
	}
	return c.publishMsg(topic, r)
}

func (c *Core) sendResult(topic string, id int64, result any) (json.RawMessage, error) {
	r, err := newJSONRPCResp(id, result)
	if err != nil {
		return nil, err
	}
	return c.publishMsg(topic, r)
}

func (c *Core) publishMsg(topic string, r *jsonrpc) (json.RawMessage, error) {
	key, ok := c.km.Get(topic)
	if !ok {
		return nil, fmt.Errorf("no key found for topic %s", topic)
	}

	data, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}

	encryptedMsg, err := chacha20poly1305Encrypt(data, key)
	if err != nil {
		return nil, err
	}

	return c.RpcHub.Call(context.Background(), "irn_publish", map[string]any{
		"topic":   topic,
		"message": base64.StdEncoding.EncodeToString(append([]byte{0x00}, encryptedMsg...)),
		"ttl":     300,
		"tag":     0,
		"prompt":  false,
	})
}

func (c *Core) subscribeTopic(topic string, ch chan json.RawMessage) error {
	if c.RpcHub == nil {
		urlStr := fmt.Sprintf("%s?auth=%s&projectId=%s", DefaultRelayer, lo.Must(c.km.GetRelayerJwtAuth(DefaultRelayer)), c.ProjectId)

		slog.Debug("[Core] dialing relayer", "url", urlStr)

		err := c.dial(urlStr, nil)
		if err != nil {
			return err
		}
	}

	ctx := context.Background()
	c.topicSubs[topic] = ch

	rpcSub, err := c.RpcHub.Subscribe(ctx, "irn", map[string]any{
		"topic": topic,
	}, c.subRecvChan)
	if err != nil {
		return err
	}

	slog.Debug("[Core] subscribed", "subId", rpcSub.ID(), "topic", topic)
	return nil
}

func (c *Core) Pair(wcStr string) error {
	symKey, err := parseWcStr(wcStr)
	if err != nil {
		return err
	}

	paringTopic := c.km.Set(symKey)
	paringTopicChan := make(chan json.RawMessage)

	err = c.subscribeTopic(paringTopic, paringTopicChan)
	if err != nil {
		return err
	}

	msg := <-paringTopicChan

	var settleApproveRpc jsonrpc
	if err := json.Unmarshal(msg, &settleApproveRpc); err != nil {
		return err
	}
	var proposeParams sessionProposeParams
	if err := json.Unmarshal(settleApproveRpc.Params, &proposeParams); err != nil {
		return err
	}

	dappPubData := lo.Must(hex.DecodeString(proposeParams.Proposer.PublicKey))
	dappPubKey := lo.Must(ecdh.X25519().NewPublicKey(dappPubData))
	sharedKey := lo.Must(c.km.DeriveSharedKey(dappPubKey))
	newTopic := c.km.Set(sharedKey)

	newTopicChan := make(chan json.RawMessage)
	lo.Must0(c.subscribeTopic(newTopic, newTopicChan))

	result := lo.Must(c.sendRequest(newTopic, "wc_sessionSettle", map[string]any{
		"relay": map[string]any{
			"protocol": "irn",
		},
		"controller": map[string]any{
			"publicKey": hex.EncodeToString(c.km.walletPrivKey.PublicKey().Bytes()),
			"metadata": map[string]any{
				"name":        "WalletConnect",
				"description": "WalletConnect",
			},
		},
		"namespaces": map[string]any{
			"eip155": map[string]any{
				"accounts": []string{"eip155:1:" + common.HexToAddress("0xF977814e90dA44bFA03b6295A0616a897441aceC").Hex()},
				"chains":   proposeParams.OptionalNamespaces.EIP155.Chains,
				"methods":  proposeParams.OptionalNamespaces.EIP155.Methods,
				"events":   proposeParams.OptionalNamespaces.EIP155.Events,
			},
		},
		"expiry": time.Now().Add(time.Hour).Unix(),
	}))
	fmt.Println(string(result))

	result = lo.Must(c.sendResult(paringTopic, settleApproveRpc.ID, map[string]any{
		"relay": map[string]any{
			"protocol": "irn",
		},
		"responderPublicKey": hex.EncodeToString(c.km.walletPrivKey.PublicKey().Bytes()),
	}))
	fmt.Println(string(result))

	for msg := range newTopicChan {
		fmt.Println("recv:", string(msg))
	}

	return nil
}

func parseWcStr(wcStr string) (symKey []byte, err error) {
	u, err := url.Parse(wcStr)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(u.Query().Get("symKey"))
}

type IRNSubscription struct {
	Topic       string `json:"topic"`
	Message     string `json:"message"`
	Attestation string `json:"attestation"`
	PublishedAt int64  `json:"publishedAt"`
	Tag         int64  `json:"tag"`
}

type sessionProposeParams struct {
	RequiredNamespaces any `json:"requiredNamespaces"`
	OptionalNamespaces struct {
		EIP155 struct {
			Chains  []string          `json:"chains"`
			Methods []string          `json:"methods"`
			Events  []string          `json:"events"`
			RPCMap  map[string]string `json:"rpcMap"`
		} `json:"eip155"`
	} `json:"optionalNamespaces"`
	Relays []struct {
		Protocol string `json:"protocol"`
	} `json:"relays"`
	Proposer struct {
		PublicKey string `json:"publicKey"`
		Metadata  struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			URL         string   `json:"url"`
			Icons       []string `json:"icons"`
		} `json:"metadata"`
	} `json:"proposer"`
	ExpiryTimestamp int64  `json:"expiryTimestamp"`
	PairingTopic    string `json:"pairingTopic"`
}
