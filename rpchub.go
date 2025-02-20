package walletconnectgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/panjf2000/ants/v2"
	"github.com/samber/lo"
)

type Subscription interface {
	ID() string
	Namespace() string
}

type rpcSubscription struct {
	id        string
	namespace string
}

func (s rpcSubscription) ID() string {
	return s.id
}

func (s rpcSubscription) Namespace() string {
	return s.namespace
}

type RpcHub interface {
	Call(ctx context.Context, method string, params any) (json.RawMessage, error)
	Subscribe(ctx context.Context, namespace string, params any, ch chan json.RawMessage) (Subscription, error)
	Unsubscribe(ctx context.Context, sub Subscription) error
	Err() chan error
}

func WithWebsocket(wsConn *websocket.Conn) RpcHub {
	h := &hub{
		wsConn:        wsConn,
		errCh:         make(chan error),
		subscriptions: make(map[string]chan json.RawMessage),
		resultWaiters: make(map[int64]chan json.RawMessage),
	}
	go h.reader()
	return h
}

type jsonrpc struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
}

func newJSONRPCReq(method string, params any) (*jsonrpc, error) {
	return newJSONRPC(time.Now().UnixNano(), method, params, nil)
}

func newJSONRPCResp(id int64, result any) (*jsonrpc, error) {
	return newJSONRPC(id, "", nil, result)
}

func newJSONRPC(id int64, method string, params, result any) (*jsonrpc, error) {
	rpc := &jsonrpc{
		JSONRPC: "2.0",
		ID:      id,
		Method:  method,
	}

	if params != nil {
		paramsBytes, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		rpc.Params = paramsBytes
	}

	if result != nil {
		resultBytes, err := json.Marshal(result)
		if err != nil {
			return nil, err
		}
		rpc.Result = resultBytes
	}

	return rpc, nil
}

type subscriptionParams struct {
	Id   string          `json:"id"`
	Data json.RawMessage `json:"data"`
}

type hub struct {
	wsConn        *websocket.Conn
	errCh         chan error
	subscriptions map[string]chan json.RawMessage
	resultWaiters map[int64]chan json.RawMessage
}

func (h *hub) waitOnce(ctx context.Context, id int64) (json.RawMessage, error) {
	ch := make(chan json.RawMessage, 1)
	defer close(ch)

	h.resultWaiters[id] = ch

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case msg := <-ch:
		return msg, nil
	}
}

func (h *hub) reader() {
	p := lo.Must(ants.NewPool(runtime.NumCPU()))
	defer p.Release()

	for {
		_, msg, err := h.wsConn.ReadMessage()
		if err != nil {
			h.errCh <- err
			if errors.Is(err, io.EOF) {
				return
			}
			continue
		}

		p.Submit(func() {
			h.dispatch(msg)
		})
	}
}

func (h *hub) write(r *jsonrpc) error {
	if r == nil {
		return nil
	}

	msg, err := json.Marshal(r)
	if err != nil {
		return err
	}

	return h.wsConn.WriteMessage(websocket.TextMessage, msg)
}

func (h *hub) dispatch(msg []byte) {
	var rpc jsonrpc
	if err := json.Unmarshal(msg, &rpc); err != nil {
		h.errCh <- err
		return
	}

	switch {
	case rpc.Result != nil:
		if ch, ok := h.resultWaiters[rpc.ID]; ok {
			ch <- rpc.Result
			delete(h.resultWaiters, rpc.ID)
		} else {
			h.errCh <- fmt.Errorf("unexpected result: %s", string(msg))
		}
	case rpc.Params != nil:
		respRpc, err := newJSONRPCResp(rpc.ID, true)
		if err != nil {
			h.errCh <- err
			return
		}
		if err := h.write(respRpc); err != nil {
			h.errCh <- err
			return
		}

		if strings.HasSuffix(rpc.Method, "_subscription") {
			var params subscriptionParams
			if err := json.Unmarshal(rpc.Params, &params); err != nil {
				h.errCh <- err
				return
			}

			if ch, ok := h.subscriptions[params.Id]; ok {
				ch <- params.Data
			} else {
				h.errCh <- fmt.Errorf("unexpected subscription: %s", string(msg))
			}

			return
		}

		h.errCh <- fmt.Errorf("unexpected method: %s", string(msg))
	default:
		h.errCh <- fmt.Errorf("unexpected message: %s", string(msg))
	}
}

func (h *hub) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	rpc, err := newJSONRPCReq(method, params)
	if err != nil {
		return nil, err
	}

	if err = h.write(rpc); err != nil {
		return nil, err
	}

	result, err := h.waitOnce(ctx, rpc.ID)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func (h *hub) Subscribe(ctx context.Context, namespace string, params any, ch chan json.RawMessage) (Subscription, error) {
	method := fmt.Sprintf("%s_subscribe", namespace)

	result, err := h.Call(ctx, method, params)
	if err != nil {
		return nil, err
	}

	var subId string
	if err = json.Unmarshal(result, &subId); err != nil {
		return nil, err
	}

	h.subscriptions[subId] = ch
	return rpcSubscription{
		id:        subId,
		namespace: namespace,
	}, nil
}

func (h *hub) Unsubscribe(ctx context.Context, sub Subscription) error {
	method := fmt.Sprintf("%s_unsubscribe", sub.Namespace())

	result, err := h.Call(ctx, method, sub)
	if err != nil {
		return err
	}

	var ok bool
	if err = json.Unmarshal(result, &ok); err != nil {
		return err
	}

	if !ok {
		return errors.New("unsubscription failed")
	}

	return nil
}

func (h *hub) Err() chan error {
	return h.errCh
}
