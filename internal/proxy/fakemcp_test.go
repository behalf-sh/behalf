package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"
)

// A fake MCP server, hermetic and network-free: the test binary re-execs
// itself with BEHALF_FAKE_MCP=1 and TestMain routes into runFakeServer
// instead of the test suite. It speaks newline-delimited JSON-RPC over
// stdio the way MCP revision 2026-07-28 does — stateless, no session to
// track — and exposes two tools, `orders.search` and `refund.issue`.
//
// Env knobs, all read by the child:
//
//	FAKE_IN_WITNESS   append every line the server RECEIVED, verbatim
//	FAKE_OUT_WITNESS  append every line the server SENT, verbatim
//	FAKE_DIE_AFTER    exit without answering the Nth tools/call (crash case)
//	FAKE_REVERSE      answer tools/call requests in pairs, reversed
//	FAKE_PUSH         emit a server->client request and a notification
const (
	envFakeServer = "BEHALF_FAKE_MCP"
	envInWitness  = "FAKE_IN_WITNESS"
	envOutWitness = "FAKE_OUT_WITNESS"
	envDieAfter   = "FAKE_DIE_AFTER"
	envReverse    = "FAKE_REVERSE"
	envPush       = "FAKE_PUSH"
)

func TestMain(m *testing.M) {
	if os.Getenv(envFakeServer) == "1" {
		os.Exit(runFakeServer())
	}
	os.Exit(m.Run())
}

func runFakeServer() int {
	inWitness := os.Getenv(envInWitness)
	outWitness := os.Getenv(envOutWitness)
	dieAfter, _ := strconv.Atoi(os.Getenv(envDieAfter))
	reverse := os.Getenv(envReverse) == "1"
	push := os.Getenv(envPush) == "1"

	send := func(line []byte) {
		witness(outWitness, line)
		os.Stdout.Write(line)
	}

	r := bufio.NewReader(os.Stdin)
	calls := 0
	var held [][]byte
	for {
		line, readErr := r.ReadBytes('\n')
		if len(line) > 0 {
			witness(inWitness, line)
			resp, isCall := fakeHandle(line)
			if isCall {
				calls++
				if dieAfter > 0 && calls >= dieAfter {
					// The payment fired and the agent died: the request was
					// received, the response never comes.
					return 0
				}
			}
			if push && methodOf(line) == "tools/list" {
				send([]byte(`{"jsonrpc":"2.0","id":"srv-1","method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"ping"}}],"maxTokens":16}}` + "\n"))
				send([]byte(`{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","logger":"fake","data":"listing tools"}}` + "\n"))
			}
			if resp != nil {
				switch {
				case reverse && isCall:
					held = append(held, resp)
					if len(held) == 2 {
						send(held[1])
						send(held[0])
						held = nil
					}
				default:
					send(resp)
				}
			}
		}
		if readErr != nil {
			break
		}
	}
	for i := len(held) - 1; i >= 0; i-- {
		send(held[i])
	}
	return 0
}

// fakeHandle returns the response line (nil for notifications) and whether
// the request was a tools/call.
func fakeHandle(line []byte) ([]byte, bool) {
	var req struct {
		Method string          `json:"method"`
		ID     json.RawMessage `json:"id"`
		Params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, false
	}
	if len(req.ID) == 0 {
		return nil, false // a notification, or a client->server response
	}
	if req.Method == "" {
		return nil, false // a response to one of our own requests
	}
	switch req.Method {
	case "initialize":
		return result(req.ID, `{"protocolVersion":"2026-07-28","capabilities":{"tools":{}},"serverInfo":{"name":"fake-orders","version":"0.1.0"}}`), false
	case "tools/list":
		return result(req.ID, `{"tools":[{"name":"orders.search","description":"search orders","inputSchema":{"type":"object","properties":{"query":{"type":"string"}}}},{"name":"refund.issue","description":"issue a refund","inputSchema":{"type":"object","properties":{"order_id":{"type":"string"},"amount":{"type":"string"}}}}]}`), false
	case "tools/call":
		return fakeToolCall(req.ID, req.Params.Name, req.Params.Arguments), true
	default:
		return rpcError(req.ID, -32601, "method not found: "+req.Method), false
	}
}

func fakeToolCall(id json.RawMessage, name string, args map[string]any) []byte {
	switch name {
	case "orders.search":
		q, _ := args["query"].(string)
		return result(id, fmt.Sprintf(
			`{"content":[{"type":"text","text":"2 orders for %s"}],"structuredContent":{"orders":[{"id":"ord_5512","amount":"12.00"},{"id":"ord_5518","amount":"1200.00"}]}}`, q))
	case "refund.issue":
		order, _ := args["order_id"].(string)
		amount, _ := args["amount"].(string)
		return result(id, fmt.Sprintf(
			`{"content":[{"type":"text","text":"refunded %s"}],"structuredContent":{"refund_id":"rf_0001","order_id":%q,"amount":%q}}`, order, order, amount))
	case "orders.explode":
		return result(id, `{"content":[{"type":"text","text":"the tool failed"}],"isError":true}`)
	default:
		return rpcError(id, -32602, "unknown tool: "+name)
	}
}

func result(id json.RawMessage, body string) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, id, body) + "\n")
}

func rpcError(id json.RawMessage, code int, msg string) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q}}`, id, code, msg) + "\n")
}

func methodOf(line []byte) string {
	var m struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(line, &m)
	return m.Method
}

func witness(path string, line []byte) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	f.Write(line)
	f.Close()
}
