package upstream

import (
	"encoding/json"
	"errors"
	"strings"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

type localSchemaLoader struct{}

func (localSchemaLoader) Load(string) (any, error) {
	return nil, errors.New("external schema references are unavailable")
}

func compileResponseSchema(format ResponseFormat) (func(any) error, error) {
	if format.Type != "json_schema" || !format.Strict {
		return nil, nil
	}
	invalid := &UpstreamError{Kind: ErrKindInvalid, StatusCode: 400, Code: "invalid_json_schema", Message: "strict response_format requires a valid JSON Schema with local references"}
	if format.Schema == nil {
		return nil, invalid
	}
	const root = "urn:awsquick2api:response-schema"
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(localSchemaLoader{})
	if err := compiler.AddResource(root, format.Schema); err != nil {
		return nil, invalid
	}
	schema, err := compiler.Compile(root)
	if err != nil {
		return nil, invalid
	}
	return schema.Validate, nil
}

func (p *preparedTurn) validateJSONOutput(text string) (string, error) {
	cleaned := CleanJSONOutput(text)
	invalidErr := &UpstreamError{
		Kind:       ErrKindCompletion,
		StatusCode: 502,
		Code:       "invalid_structured_output",
		Message:    "Amazon Quick returned an invalid response for the requested output format",
	}
	if !json.Valid([]byte(cleaned)) {
		return "", invalidErr
	}
	decoder := json.NewDecoder(strings.NewReader(cleaned))
	decoder.UseNumber()
	if p.validateSchema != nil {
		var doc any
		if decoder.Decode(&doc) != nil || p.validateSchema(doc) != nil {
			return "", invalidErr
		}
		return cleaned, nil
	}
	var obj map[string]any
	if decoder.Decode(&obj) != nil || obj == nil {
		return "", invalidErr
	}
	return cleaned, nil
}
