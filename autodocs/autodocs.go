// Package autodocs provides automatic OpenAPI documentation generation
// for Go HTTP services with zero configuration and framework-agnostic design.
package autodocs

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
)

// AutoDocs is the main documentation generator
type AutoDocs struct {
	mu          sync.RWMutex
	config      Config
	spec        *openapi3.T
	routes      map[string]*RouteInfo
	schemas     map[string]*openapi3.SchemaRef
	reflector   *TypeReflector
	analyzer    *CodeAnalyzer
	initialized bool
}

// Config holds the documentation configuration
type Config struct {
	Title          string
	Version        string
	Description    string
	TermsOfService string
	Contact        *Contact
	License        *License
	Servers        []Server
	BasePath       string
	DocsPath       string
	RedocPath      string
	SpecPath       string
	DisableTryOut  bool
	Theme          Theme
	Security       []SecurityScheme
}

type Contact struct {
	Name  string `json:"name,omitempty"`
	URL   string `json:"url,omitempty"`
	Email string `json:"email,omitempty"`
}

type License struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type Server struct {
	URL         string            `json:"url"`
	Description string            `json:"description,omitempty"`
	Variables   map[string]string `json:"variables,omitempty"`
}

type Theme string

const (
	ThemeSwagger Theme = "swagger"
	ThemeRedoc   Theme = "redoc"
	ThemeDark    Theme = "dark"
	ThemeLight   Theme = "light"
)

type SecurityScheme struct {
	Type         string            `json:"type"`
	Scheme       string            `json:"scheme,omitempty"`
	BearerFormat string            `json:"bearerFormat,omitempty"`
	In           string            `json:"in,omitempty"`
	Name         string            `json:"name,omitempty"`
	Flows        map[string]string `json:"flows,omitempty"`
}

// RouteInfo contains comprehensive route information
type RouteInfo struct {
	Method        string
	Path          string
	Handler       interface{}
	Summary       string
	Description   string
	Tags          []string
	RequestType   reflect.Type
	ResponseTypes map[int]reflect.Type
	Parameters    []Parameter
	Security      []string
	Deprecated    bool
	OperationID   string
}

type Parameter struct {
	Name        string
	In          string // path, query, header, cookie
	Type        reflect.Type
	Required    bool
	Description string
	Example     interface{}
	Schema      *openapi3.SchemaRef
}

// HTTPFramework defines the interface that HTTP frameworks must implement
type HTTPFramework interface {
	// GetRoutes returns all registered routes in the framework
	GetRoutes() ([]*FrameworkRoute, error)

	// GetHandlerInfo extracts detailed information about a handler function
	GetHandlerInfo(handler interface{}) (*HandlerInfo, error)

	// RegisterHandler registers a new HTTP handler at the specified path
	RegisterHandler(method, path string, handler http.HandlerFunc) error

	// GetMiddleware returns middleware information for a route
	GetMiddleware(handler interface{}) ([]string, error)
}

// FrameworkRoute represents a route as understood by the framework
type FrameworkRoute struct {
	Method     string
	Path       string
	Handler    interface{}
	Middleware []string
	Name       string
}

// HandlerInfo contains analyzed information about a handler function
type HandlerInfo struct {
	FuncName      string
	RequestType   reflect.Type
	ResponseTypes map[int]reflect.Type
	Parameters    []Parameter
	Summary       string
	Description   string
	Tags          []string
	Security      []string
	Deprecated    bool
}

// New creates a new AutoDocs instance
func New() *AutoDocs {
	return &AutoDocs{
		routes:    make(map[string]*RouteInfo),
		schemas:   make(map[string]*openapi3.SchemaRef),
		reflector: NewTypeReflector(),
		analyzer:  NewCodeAnalyzer(),
		config: Config{
			Title:     "API Documentation",
			Version:   "1.0.0",
			DocsPath:  "/docs",
			RedocPath: "/redoc",
			SpecPath:  "/openapi.json",
			Theme:     ThemeSwagger,
		},
	}
}

// WithConfig sets the documentation configuration
func (a *AutoDocs) WithConfig(config Config) *AutoDocs {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return a
}

// Title sets the API title
func (a *AutoDocs) Title(title string) *AutoDocs {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config.Title = title
	return a
}

// Version sets the API version
func (a *AutoDocs) Version(version string) *AutoDocs {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config.Version = version
	return a
}

// Description sets the API description
func (a *AutoDocs) Description(description string) *AutoDocs {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config.Description = description
	return a
}

// AddServer adds a server to the OpenAPI specification
func (a *AutoDocs) AddServer(url, description string) *AutoDocs {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config.Servers = append(a.config.Servers, Server{
		URL:         url,
		Description: description,
	})
	return a
}

// AddSecurity adds a security scheme
func (a *AutoDocs) AddSecurity(name string, scheme SecurityScheme) *AutoDocs {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.config.Security == nil {
		a.config.Security = make([]SecurityScheme, 0)
	}
	scheme.Type = name
	a.config.Security = append(a.config.Security, scheme)
	return a
}

// ScanFramework analyzes a framework and generates documentation
func (a *AutoDocs) ScanFramework(framework HTTPFramework) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	routes, err := framework.GetRoutes()
	if err != nil {
		return fmt.Errorf("failed to get routes from framework: %w", err)
	}

	for _, route := range routes {
		handlerInfo, err := framework.GetHandlerInfo(route.Handler)
		if err != nil {
			// Log warning but continue with other routes
			continue
		}

		routeInfo := &RouteInfo{
			Method:        route.Method,
			Path:          a.normalizePath(route.Path),
			Handler:       route.Handler,
			Summary:       handlerInfo.Summary,
			Description:   handlerInfo.Description,
			Tags:          handlerInfo.Tags,
			RequestType:   handlerInfo.RequestType,
			ResponseTypes: handlerInfo.ResponseTypes,
			Parameters:    handlerInfo.Parameters,
			Security:      handlerInfo.Security,
			Deprecated:    handlerInfo.Deprecated,
			OperationID:   a.generateOperationID(route.Method, route.Path),
		}

		key := fmt.Sprintf("%s %s", route.Method, routeInfo.Path)
		a.routes[key] = routeInfo
	}

	return a.generateOpenAPISpec()
}

// ScanStandardHTTP analyzes standard net/http handlers
func (a *AutoDocs) ScanStandardHTTP(mux *http.ServeMux) error {
	// Implementation for standard HTTP mux scanning
	// This would use reflection to extract registered patterns
	return nil
}

// RegisterRoute manually registers a route for documentation
func (a *AutoDocs) RegisterRoute(method, path string, handler interface{}, options ...RouteOption) *AutoDocs {
	a.mu.Lock()
	defer a.mu.Unlock()

	routeInfo := &RouteInfo{
		Method:        strings.ToUpper(method),
		Path:          a.normalizePath(path),
		Handler:       handler,
		ResponseTypes: make(map[int]reflect.Type),
		OperationID:   a.generateOperationID(method, path),
	}

	// Apply options
	for _, option := range options {
		option(routeInfo)
	}

	// Analyze handler if not provided through options
	if routeInfo.Summary == "" || routeInfo.ResponseTypes == nil {
		if handlerInfo := a.analyzer.AnalyzeHandler(handler); handlerInfo != nil {
			if routeInfo.Summary == "" {
				routeInfo.Summary = handlerInfo.Summary
			}
			if routeInfo.Description == "" {
				routeInfo.Description = handlerInfo.Description
			}
			if routeInfo.RequestType == nil {
				routeInfo.RequestType = handlerInfo.RequestType
			}
			if len(routeInfo.ResponseTypes) == 0 {
				routeInfo.ResponseTypes = handlerInfo.ResponseTypes
			}
		}
	}

	key := fmt.Sprintf("%s %s", method, routeInfo.Path)
	a.routes[key] = routeInfo

	return a
}

// RouteOption allows customizing route documentation
type RouteOption func(*RouteInfo)

// WithSummary sets the route summary
func WithSummary(summary string) RouteOption {
	return func(r *RouteInfo) {
		r.Summary = summary
	}
}

// WithDescription sets the route description
func WithDescription(description string) RouteOption {
	return func(r *RouteInfo) {
		r.Description = description
	}
}

// WithTags sets the route tags
func WithTags(tags ...string) RouteOption {
	return func(r *RouteInfo) {
		r.Tags = tags
	}
}

// WithRequestType sets the expected request body type
func WithRequestType(t reflect.Type) RouteOption {
	return func(r *RouteInfo) {
		r.RequestType = t
	}
}

// WithResponseType sets a response type for a specific status code
func WithResponseType(statusCode int, t reflect.Type) RouteOption {
	return func(r *RouteInfo) {
		if r.ResponseTypes == nil {
			r.ResponseTypes = make(map[int]reflect.Type)
		}
		r.ResponseTypes[statusCode] = t
	}
}

// WithSecurity adds security requirements
func WithSecurity(security ...string) RouteOption {
	return func(r *RouteInfo) {
		r.Security = security
	}
}

// WithDeprecated marks the route as deprecated
func WithDeprecated() RouteOption {
	return func(r *RouteInfo) {
		r.Deprecated = true
	}
}

// ServeHTTP serves the documentation endpoints
func (a *AutoDocs) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if !a.initialized {
		a.generateOpenAPISpec()
		a.initialized = true
	}

	switch r.URL.Path {
	case a.config.SpecPath:
		a.serveOpenAPISpec(w, r)
	case a.config.DocsPath:
		a.serveSwaggerUI(w, r)
	case a.config.RedocPath:
		a.serveRedocUI(w, r)
	default:
		http.NotFound(w, r)
	}
}

// GetOpenAPISpec returns the generated OpenAPI specification
func (a *AutoDocs) GetOpenAPISpec() *openapi3.T {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.spec
}

// generateOpenAPISpec creates the OpenAPI 3.0 specification
func (a *AutoDocs) generateOpenAPISpec() error {
	spec := &openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:          a.config.Title,
			Version:        a.config.Version,
			Description:    a.config.Description,
			TermsOfService: a.config.TermsOfService,
		},
		Paths: make(openapi3.Paths),
		Components: &openapi3.Components{
			Schemas:         make(openapi3.Schemas),
			SecuritySchemes: make(openapi3.SecuritySchemes),
		},
	}

	if a.config.Contact != nil {
		spec.Info.Contact = &openapi3.Contact{
			Name:  a.config.Contact.Name,
			URL:   a.config.Contact.URL,
			Email: a.config.Contact.Email,
		}
	}

	if a.config.License != nil {
		spec.Info.License = &openapi3.License{
			Name: a.config.License.Name,
			URL:  a.config.License.URL,
		}
	}

	// Add servers
	for _, server := range a.config.Servers {
		spec.Servers = append(spec.Servers, &openapi3.Server{
			URL:         server.URL,
			Description: server.Description,
		})
	}

	// Add security schemes
	for _, security := range a.config.Security {
		securityScheme := &openapi3.SecurityScheme{
			Type:   security.Type,
			Scheme: security.Scheme,
		}
		spec.Components.SecuritySchemes[security.Type] = &openapi3.SecuritySchemeRef{
			Value: securityScheme,
		}
	}

	// Process routes
	for _, route := range a.routes {
		pathItem := spec.Paths[route.Path]
		if pathItem == nil {
			pathItem = &openapi3.PathItem{}
			spec.Paths[route.Path] = pathItem
		}

		operation := a.createOperation(route)

		switch strings.ToUpper(route.Method) {
		case "GET":
			pathItem.Get = operation
		case "POST":
			pathItem.Post = operation
		case "PUT":
			pathItem.Put = operation
		case "PATCH":
			pathItem.Patch = operation
		case "DELETE":
			pathItem.Delete = operation
		case "HEAD":
			pathItem.Head = operation
		case "OPTIONS":
			pathItem.Options = operation
		}
	}

	// Add schemas to components
	for name, schema := range a.schemas {
		spec.Components.Schemas[name] = schema
	}

	a.spec = spec
	return nil
}

// createOperation creates an OpenAPI operation from route info
func (a *AutoDocs) createOperation(route *RouteInfo) *openapi3.Operation {
	operation := &openapi3.Operation{
		OperationID: route.OperationID,
		Summary:     route.Summary,
		Description: route.Description,
		Tags:        route.Tags,
		Deprecated:  route.Deprecated,
		Parameters:  make(openapi3.Parameters, 0),
		Responses:   make(openapi3.Responses),
	}

	// Add parameters
	for _, param := range route.Parameters {
		parameter := &openapi3.Parameter{
			Name:        param.Name,
			In:          param.In,
			Required:    param.Required,
			Description: param.Description,
			Schema:      a.reflector.TypeToSchema(param.Type),
		}

		if param.Example != nil {
			parameter.Example = param.Example
		}

		operation.Parameters = append(operation.Parameters, &openapi3.ParameterRef{
			Value: parameter,
		})
	}

	// Add request body
	if route.RequestType != nil {
		requestBody := &openapi3.RequestBody{
			Required: true,
			Content: map[string]*openapi3.MediaType{
				"application/json": {
					Schema: a.reflector.TypeToSchema(route.RequestType),
				},
			},
		}
		operation.RequestBody = &openapi3.RequestBodyRef{Value: requestBody}
	}

	// Add responses
	if len(route.ResponseTypes) == 0 {
		// Default response
		operation.Responses["200"] = &openapi3.ResponseRef{
			Value: &openapi3.Response{
				Description: stringPtr("Successful response"),
			},
		}
	} else {
		for statusCode, responseType := range route.ResponseTypes {
			response := &openapi3.Response{
				Description: stringPtr(http.StatusText(statusCode)),
			}

			if responseType != nil {
				response.Content = openapi3.Content{
					"application/json": &openapi3.MediaType{
						Schema: a.reflector.TypeToSchema(responseType),
					},
				}
			}

			operation.Responses[fmt.Sprintf("%d", statusCode)] = &openapi3.ResponseRef{
				Value: response,
			}
		}
	}

	// Add security
	if len(route.Security) > 0 {
		security := make(openapi3.SecurityRequirements, 0)
		for _, sec := range route.Security {
			security = append(security, openapi3.SecurityRequirement{
				sec: []string{},
			})
		}
		operation.Security = &security
	}

	return operation
}

// normalizePath converts framework-specific path patterns to OpenAPI format
func (a *AutoDocs) normalizePath(path string) string {
	// Convert Gin-style :param to OpenAPI {param}
	result := strings.ReplaceAll(path, ":", "{")

	// Handle wildcard parameters
	result = strings.ReplaceAll(result, "*", "{")

	// Ensure parameters are properly closed
	parts := strings.Split(result, "/")
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && !strings.HasSuffix(part, "}") {
			parts[i] = part + "}"
		}
	}

	return strings.Join(parts, "/")
}

// generateOperationID creates a unique operation ID
func (a *AutoDocs) generateOperationID(method, path string) string {
	// Remove parameter braces and clean path
	cleanPath := strings.ReplaceAll(path, "{", "")
	cleanPath = strings.ReplaceAll(cleanPath, "}", "")
	cleanPath = strings.ReplaceAll(cleanPath, "/", "_")
	cleanPath = strings.Trim(cleanPath, "_")

	if cleanPath == "" {
		cleanPath = "root"
	}

	return strings.ToLower(method) + "_" + cleanPath
}

// serveOpenAPISpec serves the OpenAPI specification as JSON
func (a *AutoDocs) serveOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := json.NewEncoder(w).Encode(a.spec); err != nil {
		http.Error(w, "Failed to encode OpenAPI spec", http.StatusInternalServerError)
	}
}

// serveSwaggerUI serves the Swagger UI interface
func (a *AutoDocs) serveSwaggerUI(w http.ResponseWriter, r *http.Request) {
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>%s - Swagger UI</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.0.0/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; background: #fafafa; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.0.0/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: '%s',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.presets.standalone
            ],
            plugins: [
                SwaggerUIBundle.plugins.DownloadUrl
            ],
            layout: "StandaloneLayout",
            tryItOutEnabled: %t,
            supportedSubmitMethods: ['get', 'post', 'put', 'delete', 'patch', 'head', 'options']
        });
    </script>
</body>
</html>`, a.config.Title, a.config.SpecPath, !a.config.DisableTryOut)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// serveRedocUI serves the ReDoc interface
func (a *AutoDocs) serveRedocUI(w http.ResponseWriter, r *http.Request) {
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>%s - ReDoc</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>
        body { margin: 0; padding: 0; }
    </style>
</head>
<body>
    <redoc spec-url='%s'></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc@2.1.3/bundles/redoc.standalone.js"></script>
</body>
</html>`, a.config.Title, a.config.SpecPath)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// TypeReflector handles type reflection and schema generation
type TypeReflector struct {
	cache map[reflect.Type]*openapi3.SchemaRef
	mu    sync.RWMutex
}

// NewTypeReflector creates a new type reflector
func NewTypeReflector() *TypeReflector {
	return &TypeReflector{
		cache: make(map[reflect.Type]*openapi3.SchemaRef),
	}
}

// TypeToSchema converts a Go type to an OpenAPI schema
func (tr *TypeReflector) TypeToSchema(t reflect.Type) *openapi3.SchemaRef {
	if t == nil {
		return nil
	}

	tr.mu.RLock()
	if schema, exists := tr.cache[t]; exists {
		tr.mu.RUnlock()
		return schema
	}
	tr.mu.RUnlock()

	schema := tr.reflectType(t)

	tr.mu.Lock()
	tr.cache[t] = schema
	tr.mu.Unlock()

	return schema
}

// reflectType performs the actual type reflection
func (tr *TypeReflector) reflectType(t reflect.Type) *openapi3.SchemaRef {
	// Handle pointers
	if t.Kind() == reflect.Ptr {
		return tr.reflectType(t.Elem())
	}

	switch t.Kind() {
	case reflect.String:
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: "string"}}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: "integer"}}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: "integer", Min: float64Ptr(0)}}
	case reflect.Float32, reflect.Float64:
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: "number"}}
	case reflect.Bool:
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: "boolean"}}
	case reflect.Slice, reflect.Array:
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type:  "array",
				Items: tr.reflectType(t.Elem()),
			},
		}
	case reflect.Map:
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type: "object",
				AdditionalProperties: openapi3.AdditionalProperties{
					Schema: tr.reflectType(t.Elem()),
				},
			},
		}
	case reflect.Struct:
		return tr.reflectStruct(t)
	case reflect.Interface:
		return &openapi3.SchemaRef{Value: &openapi3.Schema{}}
	default:
		return &openapi3.SchemaRef{Value: &openapi3.Schema{Type: "object"}}
	}
}

// reflectStruct handles struct type reflection
func (tr *TypeReflector) reflectStruct(t reflect.Type) *openapi3.SchemaRef {
	// Handle time.Time specially
	if t == reflect.TypeOf(time.Time{}) {
		return &openapi3.SchemaRef{
			Value: &openapi3.Schema{
				Type:   "string",
				Format: "date-time",
			},
		}
	}

	schema := &openapi3.Schema{
		Type:       "object",
		Properties: make(openapi3.Schemas),
	}

	required := make([]string, 0)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}

		fieldName := field.Name
		if jsonTag != "" {
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" {
				fieldName = parts[0]
			}
		}

		fieldSchema := tr.reflectType(field.Type)

		// Add validation from tags
		if validateTag := field.Tag.Get("validate"); validateTag != "" {
			tr.applyValidation(fieldSchema.Value, validateTag)
		}

		// Add example from tag
		if example := field.Tag.Get("example"); example != "" {
			fieldSchema.Value.Example = example
		}

		// Add description from tag
		if description := field.Tag.Get("description"); description != "" {
			fieldSchema.Value.Description = description
		}

		schema.Properties[fieldName] = fieldSchema

		// Check if field is required
		if !strings.Contains(jsonTag, "omitempty") && field.Type.Kind() != reflect.Ptr {
			required = append(required, fieldName)
		}
	}

	if len(required) > 0 {
		schema.Required = required
	}

	return &openapi3.SchemaRef{Value: schema}
}

// applyValidation applies validation rules from struct tags
func (tr *TypeReflector) applyValidation(schema *openapi3.Schema, validation string) {
	// Basic validation parsing - can be extended
	rules := strings.Split(validation, ",")
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "required" {
			// Handled at struct level
		} else if strings.HasPrefix(rule, "min=") {
			// Handle minimum values
		} else if strings.HasPrefix(rule, "max=") {
			// Handle maximum values
		}
		// Add more validation rules as needed
	}
}

// CodeAnalyzer handles source code analysis
type CodeAnalyzer struct {
	fileSet *token.FileSet
	cache   map[uintptr]*HandlerInfo
	mu      sync.RWMutex
}

// NewCodeAnalyzer creates a new code analyzer
func NewCodeAnalyzer() *CodeAnalyzer {
	return &CodeAnalyzer{
		fileSet: token.NewFileSet(),
		cache:   make(map[uintptr]*HandlerInfo),
	}
}

// AnalyzeHandler analyzes a handler function and extracts documentation information
func (ca *CodeAnalyzer) AnalyzeHandler(handler interface{}) *HandlerInfo {
	if handler == nil {
		return nil
	}

	// Get function pointer for caching
	handlerValue := reflect.ValueOf(handler)
	if handlerValue.Kind() != reflect.Func {
		return nil
	}

	ptr := handlerValue.Pointer()

	ca.mu.RLock()
	if info, exists := ca.cache[ptr]; exists {
		ca.mu.RUnlock()
		return info
	}
	ca.mu.RUnlock()

	info := ca.analyzeFunction(handler)

	ca.mu.Lock()
	ca.cache[ptr] = info
	ca.mu.Unlock()

	return info
}

// analyzeFunction performs the actual function analysis
func (ca *CodeAnalyzer) analyzeFunction(handler interface{}) *HandlerInfo {
	handlerValue := reflect.ValueOf(handler)
	handlerType := handlerValue.Type()

	info := &HandlerInfo{
		FuncName:      runtime.FuncForPC(handlerValue.Pointer()).Name(),
		ResponseTypes: make(map[int]reflect.Type),
	}

	// Extract function name for summary
	if funcName := ca.extractFunctionName(info.FuncName); funcName != "" {
		info.Summary = ca.generateSummary(funcName)
	}

	// Analyze function signature
	ca.analyzeFunctionSignature(handlerType, info)

	// Try to analyze source code if available
	ca.analyzeSourceCode(handler, info)

	return info
}

// extractFunctionName extracts the function name from a full function path
func (ca *CodeAnalyzer) extractFunctionName(fullName string) string {
	parts := strings.Split(fullName, ".")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullName
}

// generateSummary generates a human-readable summary from function name
func (ca *CodeAnalyzer) generateSummary(funcName string) string {
	// Convert camelCase to words
	var result strings.Builder
	for i, r := range funcName {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune(' ')
		}
		if i == 0 {
			result.WriteRune(r)
		} else {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// analyzeFunctionSignature analyzes the function signature for type information
func (ca *CodeAnalyzer) analyzeFunctionSignature(funcType reflect.Type, info *HandlerInfo) {
	// For standard HTTP handlers: func(w http.ResponseWriter, r *http.Request)
	// For Gin handlers: func(c *gin.Context)
	// For Echo handlers: func(c echo.Context) error

	if funcType.NumIn() >= 1 {
		// Try to infer framework from parameter types
		firstParam := funcType.In(0)

		// Check for common patterns and extract parameter information
		ca.inferParametersFromSignature(firstParam, info)
	}
}

// inferParametersFromSignature infers parameters from function signature
func (ca *CodeAnalyzer) inferParametersFromSignature(paramType reflect.Type, info *HandlerInfo) {
	// This is where framework-specific analysis would happen
	// For now, we'll use generic analysis

	// If it's a struct type, analyze its methods to understand the framework
	if paramType.Kind() == reflect.Ptr {
		paramType = paramType.Elem()
	}

	if paramType.Kind() == reflect.Struct {
		// Look for common method patterns that indicate parameter binding
		for i := 0; i < paramType.NumMethod(); i++ {
			method := paramType.Method(i)
			switch method.Name {
			case "Param", "Query", "Header":
				// Framework supports parameter extraction
			case "JSON", "Bind", "ShouldBindJSON":
				// Framework supports JSON binding
			}
		}
	}
}

// analyzeSourceCode attempts to analyze the actual source code
func (ca *CodeAnalyzer) analyzeSourceCode(handler interface{}, info *HandlerInfo) {
	// Get the function's source file and position
	pc := reflect.ValueOf(handler).Pointer()
	fn := runtime.FuncForPC(pc)
	file, line := fn.FileLine(pc)

	if file == "" {
		return
	}

	// Parse the source file
	src, err := parser.ParseFile(ca.fileSet, file, nil, parser.ParseComments)
	if err != nil {
		return
	}

	// Find the function declaration
	ast.Inspect(src, func(n ast.Node) bool {
		if funcDecl, ok := n.(*ast.FuncDecl); ok {
			pos := ca.fileSet.Position(funcDecl.Pos())
			if pos.Line <= line && line <= ca.fileSet.Position(funcDecl.End()).Line {
				ca.analyzeFunctionBody(funcDecl, info)
				return false
			}
		}
		return true
	})
}

// analyzeFunctionBody analyzes the function body for patterns
func (ca *CodeAnalyzer) analyzeFunctionBody(funcDecl *ast.FuncDecl, info *HandlerInfo) {
	if funcDecl.Body == nil {
		return
	}

	// Look for common patterns in the function body
	ast.Inspect(funcDecl.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			ca.analyzeCallExpression(node, info)
		case *ast.AssignStmt:
			ca.analyzeAssignment(node, info)
		}
		return true
	})

	// Extract comments for documentation
	if funcDecl.Doc != nil {
		ca.extractDocumentation(funcDecl.Doc, info)
	}
}

// analyzeCallExpression analyzes function calls for patterns
func (ca *CodeAnalyzer) analyzeCallExpression(call *ast.CallExpr, info *HandlerInfo) {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		switch sel.Sel.Name {
		case "JSON":
			// Found c.JSON() call - extract status code and response type
			if len(call.Args) >= 2 {
				if statusCode := ca.extractStatusCode(call.Args[0]); statusCode > 0 {
					responseType := ca.extractTypeFromExpression(call.Args[1])
					if responseType != nil {
						info.ResponseTypes[statusCode] = responseType
					}
				}
			}
		case "ShouldBindJSON", "BindJSON", "Bind":
			// Found JSON binding - extract request type
			if len(call.Args) >= 1 {
				requestType := ca.extractTypeFromExpression(call.Args[0])
				if requestType != nil {
					info.RequestType = requestType
				}
			}
		case "Param":
			// Found parameter extraction
			if len(call.Args) >= 1 {
				if paramName := ca.extractStringLiteral(call.Args[0]); paramName != "" {
					info.Parameters = append(info.Parameters, Parameter{
						Name:     paramName,
						In:       "path",
						Required: true,
						Type:     reflect.TypeOf(""),
					})
				}
			}
		case "Query":
			// Found query parameter extraction
			if len(call.Args) >= 1 {
				if paramName := ca.extractStringLiteral(call.Args[0]); paramName != "" {
					info.Parameters = append(info.Parameters, Parameter{
						Name: paramName,
						In:   "query",
						Type: reflect.TypeOf(""),
					})
				}
			}
		}
	}
}

// analyzeAssignment analyzes variable assignments
func (ca *CodeAnalyzer) analyzeAssignment(assign *ast.AssignStmt, info *HandlerInfo) {
	// Look for struct literal assignments that might indicate response types
	for _, rhs := range assign.Rhs {
		if compLit, ok := rhs.(*ast.CompositeLit); ok {
			if responseType := ca.extractTypeFromCompositeLiteral(compLit); responseType != nil {
				// Default to 200 status if not explicitly set
				if _, exists := info.ResponseTypes[200]; !exists {
					info.ResponseTypes[200] = responseType
				}
			}
		}
	}
}

// extractStatusCode extracts HTTP status code from an expression
func (ca *CodeAnalyzer) extractStatusCode(expr ast.Expr) int {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind == token.INT {
			if code := ca.parseInt(e.Value); code >= 100 && code < 600 {
				return code
			}
		}
	case *ast.Ident:
		// Handle named constants like http.StatusOK
		if e.Name == "StatusOK" {
			return 200
		}
		// Add more status code mappings as needed
	}
	return 0
}

// extractTypeFromExpression extracts Go type from an AST expression
func (ca *CodeAnalyzer) extractTypeFromExpression(expr ast.Expr) reflect.Type {
	switch e := expr.(type) {
	case *ast.Ident:
		// Simple identifier - try to resolve type
		return ca.resolveIdentifierType(e.Name)
	case *ast.CompositeLit:
		return ca.extractTypeFromCompositeLiteral(e)
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			// Address operator - get the underlying type
			return ca.extractTypeFromExpression(e.X)
		}
	}
	return nil
}

// extractTypeFromCompositeLiteral extracts type from composite literal
func (ca *CodeAnalyzer) extractTypeFromCompositeLiteral(lit *ast.CompositeLit) reflect.Type {
	if lit.Type == nil {
		return nil
	}

	switch t := lit.Type.(type) {
	case *ast.Ident:
		return ca.resolveIdentifierType(t.Name)
	case *ast.SelectorExpr:
		// Package qualified type like user.User
		if ident, ok := t.X.(*ast.Ident); ok {
			typeName := ident.Name + "." + t.Sel.Name
			return ca.resolveIdentifierType(typeName)
		}
	}
	return nil
}

// resolveIdentifierType resolves a type name to reflect.Type
func (ca *CodeAnalyzer) resolveIdentifierType(typeName string) reflect.Type {
	// This is a simplified implementation
	// In a full implementation, you'd need to parse imports and resolve types properly
	switch typeName {
	case "string":
		return reflect.TypeOf("")
	case "int":
		return reflect.TypeOf(0)
	case "bool":
		return reflect.TypeOf(false)
	case "User":
		// This would need proper type resolution
		return nil
	default:
		return nil
	}
}

// extractStringLiteral extracts string value from a string literal
func (ca *CodeAnalyzer) extractStringLiteral(expr ast.Expr) string {
	if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		// Remove quotes
		value := lit.Value
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			return value[1 : len(value)-1]
		}
	}
	return ""
}

// parseInt parses an integer from string
func (ca *CodeAnalyzer) parseInt(s string) int {
	var result int
	for _, r := range s {
		if r >= '0' && r <= '9' {
			result = result*10 + int(r-'0')
		} else {
			return 0
		}
	}
	return result
}

// extractDocumentation extracts documentation from comments
func (ca *CodeAnalyzer) extractDocumentation(doc *ast.CommentGroup, info *HandlerInfo) {
	if doc == nil {
		return
	}

	var description strings.Builder
	var tags []string

	for _, comment := range doc.List {
		text := strings.TrimPrefix(comment.Text, "//")
		text = strings.TrimPrefix(text, "/*")
		text = strings.TrimSuffix(text, "*/")
		text = strings.TrimSpace(text)

		if text == "" {
			continue
		}

		// Look for special annotations
		if strings.HasPrefix(text, "@tag") {
			tag := strings.TrimSpace(strings.TrimPrefix(text, "@tag"))
			if tag != "" {
				tags = append(tags, tag)
			}
		} else if strings.HasPrefix(text, "@deprecated") {
			info.Deprecated = true
		} else if strings.HasPrefix(text, "@summary") {
			summary := strings.TrimSpace(strings.TrimPrefix(text, "@summary"))
			if summary != "" {
				info.Summary = summary
			}
		} else {
			// Regular comment text
			if description.Len() > 0 {
				description.WriteString(" ")
			}
			description.WriteString(text)
		}
	}

	if description.Len() > 0 && info.Description == "" {
		info.Description = description.String()
	}

	if len(tags) > 0 && len(info.Tags) == 0 {
		info.Tags = tags
	}
}

// Framework-specific adapters

// GinAdapter provides Gin framework integration
type GinAdapter struct {
	engine interface{} // *gin.Engine
}

// NewGinAdapter creates a new Gin adapter
func NewGinAdapter(engine interface{}) *GinAdapter {
	return &GinAdapter{engine: engine}
}

// GetRoutes extracts routes from Gin engine
func (ga *GinAdapter) GetRoutes() ([]*FrameworkRoute, error) {
	// This would use reflection to access Gin's internal route tree
	// Implementation depends on Gin's internal structure

	routes := make([]*FrameworkRoute, 0)

	// Use reflection to access gin.Engine.routes
	engineValue := reflect.ValueOf(ga.engine)
	if engineValue.Kind() == reflect.Ptr {
		engineValue = engineValue.Elem()
	}

	// This is a simplified implementation
	// Real implementation would need to traverse Gin's route tree

	return routes, nil
}

// GetHandlerInfo analyzes a Gin handler
func (ga *GinAdapter) GetHandlerInfo(handler interface{}) (*HandlerInfo, error) {
	analyzer := NewCodeAnalyzer()
	return analyzer.AnalyzeHandler(handler), nil
}

// RegisterHandler registers a handler with Gin
func (ga *GinAdapter) RegisterHandler(method, path string, handler http.HandlerFunc) error {
	// Convert http.HandlerFunc to gin.HandlerFunc
	// Implementation would depend on Gin's API
	return nil
}

// GetMiddleware returns middleware information
func (ga *GinAdapter) GetMiddleware(handler interface{}) ([]string, error) {
	return nil, nil
}

// EchoAdapter provides Echo framework integration
type EchoAdapter struct {
	echo interface{} // *echo.Echo
}

// NewEchoAdapter creates a new Echo adapter
func NewEchoAdapter(echo interface{}) *EchoAdapter {
	return &EchoAdapter{echo: echo}
}

// GetRoutes extracts routes from Echo
func (ea *EchoAdapter) GetRoutes() ([]*FrameworkRoute, error) {
	// Implementation for Echo route extraction
	return nil, nil
}

// GetHandlerInfo analyzes an Echo handler
func (ea *EchoAdapter) GetHandlerInfo(handler interface{}) (*HandlerInfo, error) {
	analyzer := NewCodeAnalyzer()
	return analyzer.AnalyzeHandler(handler), nil
}

// RegisterHandler registers a handler with Echo
func (ea *EchoAdapter) RegisterHandler(method, path string, handler http.HandlerFunc) error {
	return nil
}

// GetMiddleware returns middleware information
func (ea *EchoAdapter) GetMiddleware(handler interface{}) ([]string, error) {
	return nil, nil
}

// StandardHTTPAdapter provides standard net/http integration
type StandardHTTPAdapter struct {
	mux *http.ServeMux
}

// NewStandardHTTPAdapter creates a new standard HTTP adapter
func NewStandardHTTPAdapter(mux *http.ServeMux) *StandardHTTPAdapter {
	return &StandardHTTPAdapter{mux: mux}
}

// GetRoutes extracts routes from http.ServeMux
func (sha *StandardHTTPAdapter) GetRoutes() ([]*FrameworkRoute, error) {
	// This is challenging with standard ServeMux as it doesn't expose routes
	// Would need to use reflection or alternative approaches
	return nil, nil
}

// GetHandlerInfo analyzes a standard HTTP handler
func (sha *StandardHTTPAdapter) GetHandlerInfo(handler interface{}) (*HandlerInfo, error) {
	analyzer := NewCodeAnalyzer()
	return analyzer.AnalyzeHandler(handler), nil
}

// RegisterHandler registers a handler with ServeMux
func (sha *StandardHTTPAdapter) RegisterHandler(method, path string, handler http.HandlerFunc) error {
	sha.mux.HandleFunc(path, handler)
	return nil
}

// GetMiddleware returns middleware information
func (sha *StandardHTTPAdapter) GetMiddleware(handler interface{}) ([]string, error) {
	return nil, nil
}

// Utility functions for easier integration

// AutoDetectFramework attempts to automatically detect the framework
func AutoDetectFramework(router interface{}) HTTPFramework {
	routerType := reflect.TypeOf(router)

	if routerType != nil {
		typeName := routerType.String()

		switch {
		case strings.Contains(typeName, "gin.Engine"):
			return NewGinAdapter(router)
		case strings.Contains(typeName, "echo.Echo"):
			return NewEchoAdapter(router)
		case strings.Contains(typeName, "http.ServeMux"):
			if mux, ok := router.(*http.ServeMux); ok {
				return NewStandardHTTPAdapter(mux)
			}
		}
	}

	return nil
}

// QuickSetup provides a simple setup function for common use cases
func QuickSetup(router interface{}, options ...func(*AutoDocs)) *AutoDocs {
	docs := New()

	// Apply options
	for _, option := range options {
		option(docs)
	}

	// Auto-detect and scan framework
	if framework := AutoDetectFramework(router); framework != nil {
		docs.ScanFramework(framework)
	}

	return docs
}

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}

// Helper function to create float64 pointer
func float64Ptr(f float64) *float64 {
	return &f
}

// Common option functions
func WithTitle(title string) func(*AutoDocs) {
	return func(ad *AutoDocs) {
		ad.Title(title)
	}
}

func WithVersion(version string) func(*AutoDocs) {
	return func(ad *AutoDocs) {
		ad.Version(version)
	}
}

func WithDescriptionConfig(description string) func(*AutoDocs) {
	return func(ad *AutoDocs) {
		ad.Description(description)
	}
}

func WithServer(url, description string) func(*AutoDocs) {
	return func(ad *AutoDocs) {
		ad.AddServer(url, description)
	}
}

func WithBearerAuth() func(*AutoDocs) {
	return func(ad *AutoDocs) {
		ad.AddSecurity("bearerAuth", SecurityScheme{
			Type:   "http",
			Scheme: "bearer",
		})
	}
}

func WithAPIKeyAuth(name, location string) func(*AutoDocs) {
	return func(ad *AutoDocs) {
		ad.AddSecurity(name, SecurityScheme{
			Type: "apiKey",
			In:   location,
			Name: name,
		})
	}
}
