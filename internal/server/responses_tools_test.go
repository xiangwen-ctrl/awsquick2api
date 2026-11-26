package server

import (
	"bufio"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func TestResponseToolAliasUsesPortableDistinctNames(t *testing.T) {
	valid := regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	a := responseToolAlias("alpha__beta", "read")
	b := responseToolAlias("alpha", "beta__read")
	c := responseToolAlias(strings.Repeat("long_", 20), "read")
	if a == b || !valid.MatchString(a) || !valid.MatchString(b) || !valid.MatchString(c) {
		t.Fatalf("invalid aliases: %q, %q, %q", a, b, c)
	}
}

func TestResponsesNamespacedToolRoundTrip(t *testing.T) {
	alias := responseToolAlias("mcp__fixture", "read")
	mock, _ := newMockQuick(t, "", func(send func(map[string]any), prompt string) {
		if strings.Contains(prompt, "fixture-result") {
			if !strings.Contains(prompt, "name="+alias) {
				t.Error("follow-up lost the qualified tool name")
			}
			send(map[string]any{"type": "text_delta", "payload": map[string]any{"delta": "fixture received"}})
		} else {
			send(map[string]any{"type": "text_delta", "payload": map[string]any{
				"delta": `<client_tool_call>{"name":"` + alias + `","arguments":{"name":"index.txt"}}</client_tool_call>`,
			}})
		}
		completeTurn(send)
	})
	g := newTestGateway(t, mock.URL, "good_token", 2, nil)
	req := map[string]any{
		"model": "amazon-smart", "input": "Read the fixture.", "stream": true,
		"tools": []any{
			map[string]any{"type": "function", "name": "read"},
			map[string]any{"type": "namespace", "name": "mcp__fixture", "tools": []any{
				map[string]any{"type": "function", "name": "read"},
			}},
		},
	}
	post := func() *http.Response {
		t.Helper()
		raw, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		return postJSON(g.h, "/v1/responses", string(raw)).Result()
	}
	first := post()
	defer first.Body.Close()
	if first.StatusCode != 200 {
		t.Fatalf("first turn HTTP %d", first.StatusCode)
	}
	var events []map[string]any
	scanner := bufio.NewScanner(first.Body)
	for scanner.Scan() {
		data, ok := strings.CutPrefix(scanner.Text(), "data: ")
		if !ok {
			continue
		}
		var event map[string]any
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	items := map[string]map[string]any{}
	for _, ev := range events {
		kind, _ := ev["type"].(string)
		switch kind {
		case "response.output_item.added", "response.output_item.done":
			if item, ok := ev["item"].(map[string]any); ok && item["type"] == "function_call" {
				items[kind] = item
			}
		case "response.completed":
			out := ev["response"].(map[string]any)["output"].([]any)
			for _, v := range out {
				if item, ok := v.(map[string]any); ok && item["type"] == "function_call" {
					items[kind] = item
				}
			}
		}
	}
	done := items["response.output_item.done"]
	for _, kind := range []string{"response.output_item.added", "response.output_item.done", "response.completed"} {
		item := items[kind]
		if item["namespace"] != "mcp__fixture" || item["name"] != "read" || item["id"] != done["id"] || item["call_id"] != done["call_id"] {
			t.Fatalf("%s did not preserve tool identity: %v", kind, item)
		}
	}

	req["stream"] = false
	req["input"] = []any{
		map[string]any{"type": "message", "role": "user", "content": "Read the fixture."},
		done,
		map[string]any{"type": "function_call_output", "call_id": done["call_id"], "output": "fixture-result"},
	}
	follow := post()
	defer follow.Body.Close()
	var response map[string]any
	if err := json.NewDecoder(follow.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if follow.StatusCode != 200 || response["output_text"] != "fixture received" {
		t.Fatalf("follow-up did not consume tool result: HTTP %d, body %v", follow.StatusCode, response)
	}
}
