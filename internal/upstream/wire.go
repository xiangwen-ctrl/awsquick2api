// Package upstream implements the Amazon Quick desktop wire protocol (AIDP & Gateway
// AWS EventStream/CBOR over WebSocket), QBS account/quota/attachment APIs, stateful
// thread reuse, 64 KB frame fitting, and streaming client tool bridging.
package upstream

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"strings"
)

const (
	hvBoolTrue  = 0
	hvBoolFalse = 1
	hvByte      = 2
	hvShort     = 3
	hvInt       = 4
	hvLong      = 5
	hvBytes     = 6
	hvString    = 7
	hvTimestamp = 8
	hvUUID      = 9

	maxEventStreamFrame = 16 * 1024 * 1024
)

// EventStreamMessage is a single decoded AWS EventStream frame.
type EventStreamMessage struct {
	Headers map[string]any
	Payload []byte
}

// EventStreamEncode encodes string headers and payload into an AWS EventStream binary frame.
func EventStreamEncode(headers map[string]string, payload []byte) []byte {
	var hbuf bytes.Buffer
	for name, val := range headers {
		nb := []byte(name)
		vb := []byte(val)
		if len(nb) == 0 || len(nb) > 255 || len(vb) > 65535 {
			continue
		}
		hbuf.WriteByte(byte(len(nb)))
		hbuf.Write(nb)
		hbuf.WriteByte(hvString)
		_ = binary.Write(&hbuf, binary.BigEndian, uint16(len(vb)))
		hbuf.Write(vb)
	}
	hbytes := hbuf.Bytes()
	total := uint32(12 + len(hbytes) + len(payload) + 4)

	out := make([]byte, total)
	binary.BigEndian.PutUint32(out[0:4], total)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(hbytes)))
	binary.BigEndian.PutUint32(out[8:12], crc32.ChecksumIEEE(out[0:8]))
	copy(out[12:12+len(hbytes)], hbytes)
	copy(out[12+len(hbytes):total-4], payload)
	binary.BigEndian.PutUint32(out[total-4:total], crc32.ChecksumIEEE(out[:total-4]))
	return out
}

func decodeEventHeaders(b []byte) (map[string]any, error) {
	out := map[string]any{}
	i := 0
	need := func(n int, what string) error {
		if i+n > len(b) {
			return fmt.Errorf("truncated %s", what)
		}
		return nil
	}
	for i < len(b) {
		nameLen := int(b[i])
		i++
		if nameLen == 0 {
			return nil, errors.New("empty event header name")
		}
		if err := need(nameLen, "event header name"); err != nil {
			return nil, err
		}
		name := string(b[i : i+nameLen])
		i += nameLen
		if err := need(1, "event header type"); err != nil {
			return nil, err
		}
		typ := b[i]
		i++
		switch typ {
		case hvBoolTrue:
			out[name] = true
		case hvBoolFalse:
			out[name] = false
		case hvByte:
			if err := need(1, "byte header"); err != nil {
				return nil, err
			}
			out[name] = int8(b[i])
			i++
		case hvShort:
			if err := need(2, "short header"); err != nil {
				return nil, err
			}
			out[name] = int16(binary.BigEndian.Uint16(b[i : i+2]))
			i += 2
		case hvInt:
			if err := need(4, "int header"); err != nil {
				return nil, err
			}
			out[name] = int32(binary.BigEndian.Uint32(b[i : i+4]))
			i += 4
		case hvLong, hvTimestamp:
			if err := need(8, "long header"); err != nil {
				return nil, err
			}
			out[name] = int64(binary.BigEndian.Uint64(b[i : i+8]))
			i += 8
		case hvBytes, hvString:
			if err := need(2, "header length"); err != nil {
				return nil, err
			}
			n := int(binary.BigEndian.Uint16(b[i : i+2]))
			i += 2
			if err := need(n, "header value"); err != nil {
				return nil, err
			}
			val := make([]byte, n)
			copy(val, b[i:i+n])
			i += n
			if typ == hvString {
				out[name] = string(val)
			} else {
				out[name] = val
			}
		case hvUUID:
			if err := need(16, "uuid header"); err != nil {
				return nil, err
			}
			val := make([]byte, 16)
			copy(val, b[i:i+16])
			i += 16
			out[name] = val
		default:
			return nil, fmt.Errorf("unsupported event header type %d", typ)
		}
	}
	return out, nil
}

// EventStreamDecoder incrementally decodes AWS EventStream frames across WebSocket chunks.
type EventStreamDecoder struct {
	buf []byte
}

// Feed appends chunk and returns all complete validated EventStream messages.
func (d *EventStreamDecoder) Feed(chunk []byte) ([]EventStreamMessage, error) {
	if len(chunk) > 0 {
		d.buf = append(d.buf, chunk...)
	}
	var msgs []EventStreamMessage
	pos := 0
	for len(d.buf)-pos >= 12 {
		totalU32 := binary.BigEndian.Uint32(d.buf[pos : pos+4])
		headersU32 := binary.BigEndian.Uint32(d.buf[pos+4 : pos+8])
		preludeCRC := binary.BigEndian.Uint32(d.buf[pos+8 : pos+12])
		if totalU32 < 16 || totalU32 > maxEventStreamFrame || headersU32 > totalU32-16 {
			d.buf = nil
			return nil, fmt.Errorf("invalid event-stream lengths (total=%d headers=%d)", totalU32, headersU32)
		}
		total := int(totalU32)
		headersLen := int(headersU32)
		if crc32.ChecksumIEEE(d.buf[pos:pos+8]) != preludeCRC {
			d.buf = nil
			return nil, errors.New("event-stream prelude CRC mismatch")
		}
		if len(d.buf)-pos < total {
			break
		}
		frame := d.buf[pos : pos+total]
		msgCRC := binary.BigEndian.Uint32(frame[total-4 : total])
		if crc32.ChecksumIEEE(frame[:total-4]) != msgCRC {
			d.buf = nil
			return nil, errors.New("event-stream message CRC mismatch")
		}
		hdrs, err := decodeEventHeaders(frame[12 : 12+headersLen])
		if err != nil {
			d.buf = nil
			return nil, err
		}
		payload := make([]byte, total-16-headersLen)
		copy(payload, frame[12+headersLen:total-4])
		msgs = append(msgs, EventStreamMessage{
			Headers: hdrs,
			Payload: payload,
		})
		pos += total
	}
	if pos > 0 {
		rem := len(d.buf) - pos
		copy(d.buf, d.buf[pos:])
		d.buf = d.buf[:rem]
	}
	if len(d.buf) > maxEventStreamFrame {
		d.buf = nil
		return nil, errors.New("event-stream buffer overflow")
	}
	return msgs, nil
}

// EventStreamDecodeAll decodes all complete messages in data in one shot.
func EventStreamDecodeAll(data []byte) ([]EventStreamMessage, error) {
	var dec EventStreamDecoder
	return dec.Feed(data)
}

func eventHeaderString(headers map[string]any, key string) string {
	v, ok := headers[key]
	if !ok || v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		return ""
	}
}

func eventFrameError(headers map[string]any) error {
	typ := eventHeaderString(headers, ":message-type")
	if typ != "error" && typ != "exception" {
		return nil
	}
	code := eventHeaderString(headers, ":error-code")
	if code == "" {
		code = eventHeaderString(headers, ":exception-type")
	}
	msg := eventHeaderString(headers, ":error-message")
	return fmt.Errorf("upstream error [%s] %s", code, msg)
}

// --- Minimal RFC 8949 CBOR codec for Amazon Quick Gateway bidi transport ---

func cborWriteHead(buf *bytes.Buffer, major byte, n uint64) {
	m := major << 5
	switch {
	case n < 24:
		buf.WriteByte(m | byte(n))
	case n <= 0xff:
		buf.WriteByte(m | 24)
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(m | 25)
		_ = binary.Write(buf, binary.BigEndian, uint16(n))
	case n <= 0xffffffff:
		buf.WriteByte(m | 26)
		_ = binary.Write(buf, binary.BigEndian, uint32(n))
	default:
		buf.WriteByte(m | 27)
		_ = binary.Write(buf, binary.BigEndian, n)
	}
}

func cborEncodeInto(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		buf.WriteByte(0xf6)
	case bool:
		if x {
			buf.WriteByte(0xf5)
		} else {
			buf.WriteByte(0xf4)
		}
	case int:
		if x >= 0 {
			cborWriteHead(buf, 0, uint64(x))
		} else {
			cborWriteHead(buf, 1, uint64(-1-x))
		}
	case int64:
		if x >= 0 {
			cborWriteHead(buf, 0, uint64(x))
		} else {
			cborWriteHead(buf, 1, uint64(-1-x))
		}
	case uint64:
		cborWriteHead(buf, 0, x)
	case float64:
		buf.WriteByte(0xfb)
		_ = binary.Write(buf, binary.BigEndian, math.Float64bits(x))
	case []byte:
		cborWriteHead(buf, 2, uint64(len(x)))
		buf.Write(x)
	case string:
		cborWriteHead(buf, 3, uint64(len(x)))
		buf.WriteString(x)
	case []any:
		cborWriteHead(buf, 4, uint64(len(x)))
		for _, item := range x {
			if err := cborEncodeInto(buf, item); err != nil {
				return err
			}
		}
	case map[string]any:
		cborWriteHead(buf, 5, uint64(len(x)))
		for k, val := range x {
			cborWriteHead(buf, 3, uint64(len(k)))
			buf.WriteString(k)
			if err := cborEncodeInto(buf, val); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported CBOR type %T", v)
	}
	return nil
}

// CBOREncode encodes a Go value (nil, bool, int/int64/uint64/float64, []byte, string, []any, map[string]any) to CBOR.
func CBOREncode(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := cborEncodeInto(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func halfToFloat64(h uint16) float64 {
	exp := int((h >> 10) & 0x1f)
	frac := int(h & 0x3ff)
	sign := 1.0
	if h&0x8000 != 0 {
		sign = -1.0
	}
	if exp == 0 {
		return sign * math.Ldexp(float64(frac), -24)
	}
	if exp == 31 {
		if frac != 0 {
			return math.NaN()
		}
		return sign * math.Inf(1)
	}
	return sign * math.Ldexp(float64(1024+frac), exp-25)
}

func cborDecodeAt(data []byte, start int, depth int) (any, int, error) {
	if depth > 64 {
		return nil, start, errors.New("CBOR nesting too deep")
	}
	i := start
	if i >= len(data) {
		return nil, i, errors.New("truncated CBOR")
	}
	initial := data[i]
	i++
	major := initial >> 5
	info := initial & 0x1f

	need := func(n int) error {
		if n < 0 || i+n > len(data) {
			return errors.New("truncated CBOR")
		}
		return nil
	}

	var n uint64
	at := i
	switch {
	case info < 24:
		n = uint64(info)
	case info == 24:
		if err := need(1); err != nil {
			return nil, i, err
		}
		n = uint64(data[i])
		i++
	case info == 25:
		if err := need(2); err != nil {
			return nil, i, err
		}
		n = uint64(binary.BigEndian.Uint16(data[i : i+2]))
		i += 2
	case info == 26:
		if err := need(4); err != nil {
			return nil, i, err
		}
		n = uint64(binary.BigEndian.Uint32(data[i : i+4]))
		i += 4
	case info == 27:
		if err := need(8); err != nil {
			return nil, i, err
		}
		n = binary.BigEndian.Uint64(data[i : i+8])
		i += 8
	case info == 31:
		// RFC 8949 indefinite-length byte string, text string, array, or map (bounded).
		switch major {
		case 2:
			var out []byte
			chunks := 0
			for {
				if i >= len(data) {
					return nil, i, errors.New("truncated CBOR indefinite bytes")
				}
				if data[i] == 0xff {
					return out, i + 1, nil
				}
				chunks++
				if chunks > 65536 {
					return nil, i, errors.New("CBOR indefinite bytes too many chunks")
				}
				part, next, err := cborDecodeAt(data, i, depth+1)
				if err != nil {
					return nil, i, err
				}
				pb, ok := part.([]byte)
				if !ok {
					return nil, i, errors.New("CBOR indefinite bytes chunk is not bytes")
				}
				if len(out)+len(pb) > maxEventStreamFrame {
					return nil, i, errors.New("CBOR bytes too large")
				}
				out = append(out, pb...)
				i = next
			}
		case 3:
			var sb strings.Builder
			chunks := 0
			for {
				if i >= len(data) {
					return nil, i, errors.New("truncated CBOR indefinite text")
				}
				if data[i] == 0xff {
					return sb.String(), i + 1, nil
				}
				chunks++
				if chunks > 65536 {
					return nil, i, errors.New("CBOR indefinite text too many chunks")
				}
				part, next, err := cborDecodeAt(data, i, depth+1)
				if err != nil {
					return nil, i, err
				}
				ps, ok := part.(string)
				if !ok {
					return nil, i, errors.New("CBOR indefinite text chunk is not text")
				}
				if sb.Len()+len(ps) > maxEventStreamFrame {
					return nil, i, errors.New("CBOR text too large")
				}
				sb.WriteString(ps)
				i = next
			}
		case 4:
			var arr []any
			for {
				if i >= len(data) {
					return nil, i, errors.New("truncated CBOR indefinite array")
				}
				if data[i] == 0xff {
					return arr, i + 1, nil
				}
				if len(arr) >= 65536 {
					return nil, i, errors.New("CBOR array too large")
				}
				item, next, err := cborDecodeAt(data, i, depth+1)
				if err != nil {
					return nil, i, err
				}
				arr = append(arr, item)
				i = next
			}
		case 5:
			m := map[string]any{}
			entries := 0
			for {
				if i >= len(data) {
					return nil, i, errors.New("truncated CBOR indefinite map")
				}
				if data[i] == 0xff {
					return m, i + 1, nil
				}
				if entries >= 65536 {
					return nil, i, errors.New("CBOR map too large")
				}
				entries++
				key, afterKey, err := cborDecodeAt(data, i, depth+1)
				if err != nil {
					return nil, i, err
				}
				val, afterVal, err := cborDecodeAt(data, afterKey, depth+1)
				if err != nil {
					return nil, afterKey, err
				}
				var ks string
				switch kt := key.(type) {
				case string:
					ks = kt
				case []byte:
					ks = string(kt)
				default:
					ks = fmt.Sprint(kt)
				}
				m[ks] = val
				i = afterVal
			}
		default:
			return nil, i, fmt.Errorf("unsupported CBOR indefinite major type %d", major)
		}
	default:
		return nil, i, fmt.Errorf("unsupported CBOR additional info %d", info)
	}

	switch major {
	case 0:
		return n, i, nil
	case 1:
		return -1 - int64(n), i, nil
	case 2:
		if n > maxEventStreamFrame {
			return nil, i, errors.New("CBOR bytes too large")
		}
		if err := need(int(n)); err != nil {
			return nil, i, err
		}
		cp := make([]byte, n)
		copy(cp, data[i:i+int(n)])
		return cp, i + int(n), nil
	case 3:
		if n > maxEventStreamFrame {
			return nil, i, errors.New("CBOR text too large")
		}
		if err := need(int(n)); err != nil {
			return nil, i, err
		}
		return string(data[i : i+int(n)]), i + int(n), nil
	case 4:
		// Every element needs at least one byte, so a declared length larger than
		// the remaining input is malformed; rejecting it up front stops tiny
		// frames from forcing huge pre-allocations at every nesting level.
		if n > 65536 || n > uint64(len(data)-i) {
			return nil, i, errors.New("CBOR array too large")
		}
		arr := make([]any, 0, n)
		for k := uint64(0); k < n; k++ {
			item, next, err := cborDecodeAt(data, i, depth+1)
			if err != nil {
				return nil, i, err
			}
			arr = append(arr, item)
			i = next
		}
		return arr, i, nil
	case 5:
		// Each key/value pair needs at least two bytes.
		if n > 65536 || n > uint64(len(data)-i)/2 {
			return nil, i, errors.New("CBOR map too large")
		}
		m := make(map[string]any, n)
		for k := uint64(0); k < n; k++ {
			key, afterKey, err := cborDecodeAt(data, i, depth+1)
			if err != nil {
				return nil, i, err
			}
			val, afterVal, err := cborDecodeAt(data, afterKey, depth+1)
			if err != nil {
				return nil, afterKey, err
			}
			var ks string
			switch kt := key.(type) {
			case string:
				ks = kt
			case []byte:
				ks = string(kt)
			default:
				ks = fmt.Sprint(kt)
			}
			m[ks] = val
			i = afterVal
		}
		return m, i, nil
	case 6:
		return cborDecodeAt(data, i, depth+1)
	default:
		switch info {
		case 20:
			return false, i, nil
		case 21:
			return true, i, nil
		case 22, 23:
			return nil, i, nil
		case 25:
			return halfToFloat64(binary.BigEndian.Uint16(data[at : at+2])), i, nil
		case 26:
			return float64(math.Float32frombits(binary.BigEndian.Uint32(data[at : at+4]))), i, nil
		case 27:
			return math.Float64frombits(binary.BigEndian.Uint64(data[at : at+8])), i, nil
		default:
			return nil, i, fmt.Errorf("unsupported CBOR simple value %d", info)
		}
	}
}

// CBORDecode decodes a single CBOR item from data.
func CBORDecode(data []byte) (any, error) {
	v, _, err := cborDecodeAt(data, 0, 0)
	return v, err
}

// --- AIDP & Gateway frame codecs ---

// EncodeAIDP wraps a JSON payload string into the outbound AIDP envelope:
// {"eventType":"rawInputEvent","payload":{"payload":"<base64>"}}
func EncodeAIDP(jsonBytes []byte) ([]byte, error) {
	env := map[string]any{
		"eventType": "rawInputEvent",
		"payload": map[string]any{
			"payload": base64.StdEncoding.EncodeToString(jsonBytes),
		},
	}
	return json.Marshal(env)
}

// EncodeGateway wraps a JSON payload into an AWS EventStream frame with CBOR {"payload": jsonBytes}.
func EncodeGateway(jsonBytes []byte) ([]byte, error) {
	cborBytes, err := CBOREncode(map[string]any{"payload": jsonBytes})
	if err != nil {
		return nil, err
	}
	return EventStreamEncode(map[string]string{
		":event-type":   "rawInputEvent",
		":content-type": "application/cbor",
		":message-type": "event",
	}, cborBytes), nil
}

// WireDecoder incrementally decodes inbound WebSocket binary frames for AIDP or Gateway.
type WireDecoder struct {
	gateway bool
	es      EventStreamDecoder
}

func NewWireDecoder(gateway bool) *WireDecoder {
	return &WireDecoder{gateway: gateway}
}

// Feed decodes one inbound binary WebSocket message into zero or more raw JSON event strings.
func (w *WireDecoder) Feed(data []byte) ([]string, error) {
	msgs, err := w.es.Feed(data)
	if err != nil || len(msgs) == 0 {
		// Fallback for servers that answer AIDP with a plain JSON object frame.
		if !w.gateway && len(w.es.buf) == 0 {
			trimmed := bytes.TrimSpace(data)
			if len(trimmed) > 0 && trimmed[0] == '{' {
				var probe map[string]any
				if json.Unmarshal(trimmed, &probe) == nil && probe != nil {
					return []string{string(trimmed)}, nil
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("decode event-stream: %w", err)
		}
		return nil, nil
	}

	out := make([]string, 0, len(msgs))
	for _, msg := range msgs {
		if ferr := eventFrameError(msg.Headers); ferr != nil {
			return nil, ferr
		}
		if len(msg.Payload) == 0 {
			continue
		}
		if !w.gateway {
			if evType := eventHeaderString(msg.Headers, ":event-type"); evType != "" && evType != "rawOutputEvent" {
				continue
			}
			var outer struct {
				Payload string `json:"payload"`
			}
			if err := json.Unmarshal(msg.Payload, &outer); err != nil {
				return nil, fmt.Errorf("decode AIDP body: %w", err)
			}
			if outer.Payload == "" {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(outer.Payload)
			if err != nil {
				return nil, fmt.Errorf("decode AIDP base64: %w", err)
			}
			out = append(out, string(raw))
		} else {
			val, err := CBORDecode(msg.Payload)
			if err != nil {
				return nil, fmt.Errorf("decode gateway CBOR: %w", err)
			}
			m, ok := val.(map[string]any)
			if !ok {
				return nil, errors.New("gateway CBOR payload is not a map")
			}
			switch p := m["payload"].(type) {
			case []byte:
				out = append(out, string(p))
			case string:
				out = append(out, p)
			default:
				if len(m) == 0 {
					continue
				}
				return nil, errors.New("gateway CBOR missing payload field")
			}
		}
	}
	return out, nil
}

// FrameBytes returns the byte size Amazon Quick counts against its 64 KB message limit.
func FrameBytes(gateway bool, value any) int {
	raw, err := json.Marshal(value)
	if err != nil {
		return 0
	}
	if !gateway {
		return len(raw)
	}
	encoded, err := EncodeGateway(raw)
	if err != nil {
		return len(raw)
	}
	return len(encoded)
}

func isUpstreamErrorFrame(err error) bool {
	return err != nil && strings.HasPrefix(err.Error(), "upstream error [")
}
