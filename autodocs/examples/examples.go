// Package examples demonstrates various usage patterns of the autodocs library
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"time"

	"go-autodocs/autodocs"

	"github.com/gin-gonic/gin"
)

// Domain models with rich struct tags for automatic schema generation
type User struct {
	ID        int       `json:"id" example:"1" description:"Unique user identifier"`
	Name      string    `json:"name" example:"John Doe" description:"Full name of the user" validate:"required,min=2,max=100"`
	Email     string    `json:"email" example:"john.doe@example.com" description:"User's email address" validate:"required,email"`
	Age       int       `json:"age" example:"30" description:"User's age" validate:"min=18,max=120"`
	IsActive  bool      `json:"is_active" example:"true" description:"Whether the user account is active"`
	CreatedAt time.Time `json:"created_at" example:"2024-01-15T10:30:00Z" description:"Account creation timestamp"`
	Profile   *Profile  `json:"profile,omitempty" description:"User's profile information"`
}

type Profile struct {
	Bio         string            `json:"bio" example:"Software engineer passionate about Go" description:"User biography"`
	Skills      []string          `json:"skills" example:"Go,Docker,Kubernetes" description:"List of user skills"`
	Location    string            `json:"location" example:"San Francisco, CA" description:"User's location"`
	Website     string            `json:"website" example:"https://johndoe.dev" description:"Personal website URL"`
	SocialLinks map[string]string `json:"social_links" example:"{\"twitter\":\"@johndoe\",\"github\":\"johndoe\"}" description:"Social media links"`
}

type CreateUserRequest struct {
	Name     string   `json:"name" example:"Jane Smith" validate:"required,min=2,max=100"`
	Email    string   `json:"email" example:"jane.smith@example.com" validate:"required,email"`
	Age      int      `json:"age" example:"28" validate:"min=18,max=120"`
	Skills   []string `json:"skills" example:"Python,JavaScript,React"`
	Location string   `json:"location" example:"New York, NY"`
}

type UpdateUserRequest struct {
	Name     *string `json:"name,omitempty" example:"Jane Doe"`
	Email    *string `json:"email,omitempty" example:"jane.doe@example.com"`
	Age      *int    `json:"age,omitempty" example:"29"`
	IsActive *bool   `json:"is_active,omitempty" example:"false"`
}

type ErrorResponse struct {
	Error   string `json:"error" example:"User not found" description:"Error message"`
	Code    int    `json:"code" example:"404" description:"Error code"`
	Details string `json:"details,omitempty" example:"User with ID 123 does not exist" description:"Additional error details"`
}

type PaginatedUsersResponse struct {
	Users      []User `json:"users" description:"List of users"`
	Total      int    `json:"total" example:"150" description:"Total number of users"`
	Page       int    `json:"page" example:"1" description:"Current page number"`
	PageSize   int    `json:"page_size" example:"20" description:"Number of items per page"`
	TotalPages int    `json:"total_pages" example:"8" description:"Total number of pages"`
}

// Example 1: Framework-Agnostic with Gin (Zero Configuration)
func ExampleGinZeroConfig() {
	r := gin.Default()

	// Define your routes normally - no annotations needed!
	r.GET("/users/:id", GetUser)
	r.POST("/users", CreateUser)
	r.PUT("/users/:id", UpdateUser)
	r.DELETE("/users/:id", DeleteUser)
	r.GET("/users", ListUsers)

	// One-line setup for automatic documentation
	docs := autodocs.QuickSetup(r,
		autodocs.WithTitle("User Management API"),
		autodocs.WithVersion("1.0.0"),
		//autodocs.WithDescription("a comprehensive user management system with automatic API documentation"),
		autodocs.WithServer("http://localhost:8080", "Development server"),
		autodocs.WithBearerAuth(),
	)

	// Register documentation endpoints
	r.Any("/docs/*any", gin.WrapH(docs))
	r.Any("/redoc/*any", gin.WrapH(docs))
	r.Any("/openapi.json", gin.WrapH(docs))

	log.Println("🚀 Server starting on :8080")
	log.Println("📚 API Documentation: http://localhost:8080/docs")
	log.Println("📖 ReDoc Documentation: http://localhost:8080/redoc")
	log.Println("📋 OpenAPI Spec: http://localhost:8080/openapi.json")

	r.Run(":8080")
}

// Example 2: Manual Route Registration with Rich Options
func ExampleManualRegistration() {
	docs := autodocs.New().
		Title("Advanced User API").
		Version("2.0.0").
		Description("Production-grade user management API with comprehensive documentation").
		AddServer("https://api.example.com", "Production server").
		AddServer("https://staging.example.com", "Staging server").
		AddSecurity("bearerAuth", autodocs.SecurityScheme{
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
		}).
		AddSecurity("apiKey", autodocs.SecurityScheme{
			Type: "apiKey",
			In:   "header",
			Name: "X-API-Key",
		})

	// Register routes with detailed documentation
	docs.RegisterRoute("GET", "/users/{id}", GetUser,
		autodocs.WithSummary("Retrieve user by ID"),
		autodocs.WithDescription("Fetches a single user by their unique identifier. Returns full user profile including personal information and account status."),
		autodocs.WithTags("users", "profiles"),
		autodocs.WithResponseType(200, reflect.TypeOf(User{})),
		autodocs.WithResponseType(404, reflect.TypeOf(ErrorResponse{})),
		autodocs.WithResponseType(500, reflect.TypeOf(ErrorResponse{})),
		autodocs.WithSecurity("bearerAuth"),
	)

	docs.RegisterRoute("POST", "/users", CreateUser,
		autodocs.WithSummary("Create new user"),
		autodocs.WithDescription("Creates a new user account with the provided information. Email must be unique across the system."),
		autodocs.WithTags("users"),
		autodocs.WithRequestType(reflect.TypeOf(CreateUserRequest{})),
		autodocs.WithResponseType(201, reflect.TypeOf(User{})),
		autodocs.WithResponseType(400, reflect.TypeOf(ErrorResponse{})),
		autodocs.WithResponseType(409, reflect.TypeOf(ErrorResponse{})),
		autodocs.WithSecurity("bearerAuth"),
	)

	docs.RegisterRoute("PUT", "/users/{id}", UpdateUser,
		autodocs.WithSummary("Update user information"),
		autodocs.WithDescription("Updates an existing user's information. Only provided fields will be updated."),
		autodocs.WithTags("users"),
		autodocs.WithRequestType(reflect.TypeOf(UpdateUserRequest{})),
		autodocs.WithResponseType(200, reflect.TypeOf(User{})),
		autodocs.WithResponseType(404, reflect.TypeOf(ErrorResponse{})),
		autodocs.WithResponseType(400, reflect.TypeOf(ErrorResponse{})),
		autodocs.WithSecurity("bearerAuth"),
	)

	docs.RegisterRoute("DELETE", "/users/{id}", DeleteUser,
		autodocs.WithSummary("Delete user account"),
		autodocs.WithDescription("Permanently deletes a user account. This action cannot be undone."),
		autodocs.WithTags("users"),
		autodocs.WithResponseType(204, nil),
		autodocs.WithResponseType(404, reflect.TypeOf(ErrorResponse{})),
		autodocs.WithSecurity("bearerAuth"),
	)

	docs.RegisterRoute("GET", "/users", ListUsers,
		autodocs.WithSummary("List all users"),
		autodocs.WithDescription("Retrieves a paginated list of all users in the system with optional filtering."),
		autodocs.WithTags("users"),
		autodocs.WithResponseType(200, reflect.TypeOf(PaginatedUsersResponse{})),
		autodocs.WithSecurity("bearerAuth"),
	)

	// Serve documentation
	http.Handle("/docs/", docs)
	http.Handle("/redoc/", docs)
	http.Handle("/openapi.json", docs)

	log.Println("📚 Documentation server running on :8080")
	http.ListenAndServe(":8080", nil)
}

// Example 3: Framework-Agnostic with Standard HTTP
func ExampleStandardHTTP() {
	mux := http.NewServeMux()

	// Register your handlers
	mux.HandleFunc("/users/", handleUsers)
	mux.HandleFunc("/health", healthCheck)

	// Auto-generate documentation
	docs := autodocs.QuickSetup(mux,
		autodocs.WithTitle("Standard HTTP API"),
		autodocs.WithVersion("1.0.0"),
		autodocs.WithAPIKeyAuth("X-API-Key", "header"),
	)

	// Add documentation routes
	mux.Handle("/docs/", docs)
	mux.Handle("/openapi.json", docs)

	log.Println("🌐 Standard HTTP server with docs on :8080")
	http.ListenAndServe(":8080", mux)
}

// Handler implementations that work with zero annotations
// The library automatically infers types from these patterns

// GetUser retrieves a user by ID
// The library automatically detects:
// - Path parameter "id" from c.Param("id")
// - Response type User from c.JSON(200, user)
// - Error responses from various c.JSON calls
func GetUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(400, ErrorResponse{
			Error:   "Invalid user ID",
			Code:    400,
			Details: "User ID must be a valid integer",
		})
		return
	}

	// Simulate database lookup
	if id == 999 {
		c.JSON(404, ErrorResponse{
			Error:   "User not found",
			Code:    404,
			Details: "User with the specified ID does not exist",
		})
		return
	}

	// The library detects this response type automatically
	user := User{
		ID:        id,
		Name:      "John Doe",
		Email:     "john.doe@example.com",
		Age:       30,
		IsActive:  true,
		CreatedAt: time.Now(),
		Profile: &Profile{
			Bio:      "Software engineer passionate about Go",
			Skills:   []string{"Go", "Docker", "Kubernetes"},
			Location: "San Francisco, CA",
			Website:  "https://johndoe.dev",
			SocialLinks: map[string]string{
				"twitter": "@johndoe",
				"github":  "johndoe",
			},
		},
	}

	c.JSON(200, user)
}

// CreateUser creates a new user
// Library detects:
// - Request type from c.ShouldBindJSON(&req)
// - Success response type from c.JSON(201, user)
// - Error response types from error cases
func CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{
			Error:   "Invalid request body",
			Code:    400,
			Details: err.Error(),
		})
		return
	}

	// Simulate email uniqueness check
	if req.Email == "taken@example.com" {
		c.JSON(409, ErrorResponse{
			Error:   "Email already exists",
			Code:    409,
			Details: "A user with this email address already exists",
		})
		return
	}

	// Create new user
	user := User{
		ID:        42,
		Name:      req.Name,
		Email:     req.Email,
		Age:       req.Age,
		IsActive:  true,
		CreatedAt: time.Now(),
		Profile: &Profile{
			Skills:   req.Skills,
			Location: req.Location,
		},
	}

	c.JSON(201, user)
}

// UpdateUser updates an existing user
func UpdateUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(400, ErrorResponse{Error: "Invalid user ID", Code: 400})
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: "Invalid request body", Code: 400})
		return
	}

	// Simulate user not found
	if id == 999 {
		c.JSON(404, ErrorResponse{Error: "User not found", Code: 404})
		return
	}

	// Simulate update and return updated user
	user := User{
		ID:        id,
		Name:      "Updated Name",
		Email:     "updated@example.com",
		Age:       31,
		IsActive:  true,
		CreatedAt: time.Now().Add(-24 * time.Hour),
	}

	// Apply updates from request
	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.Age != nil {
		user.Age = *req.Age
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}

	c.JSON(200, user)
}

// DeleteUser removes a user account
func DeleteUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(400, ErrorResponse{Error: "Invalid user ID", Code: 400})
		return
	}

	// Simulate user not found
	if id == 999 {
		c.JSON(404, ErrorResponse{Error: "User not found", Code: 404})
		return
	}

	// Successful deletion returns 204 No Content
	c.Status(204)
}

// ListUsers returns a paginated list of users
// Library detects query parameters from c.Query() calls
func ListUsers(c *gin.Context) {
	// Extract pagination parameters
	page := 1
	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	pageSize := 20
	if sizeStr := c.Query("page_size"); sizeStr != "" {
		if s, err := strconv.Atoi(sizeStr); err == nil && s > 0 && s <= 100 {
			pageSize = s
		}
	}

	// Extract filter parameters
	status := c.Query("status")     // active, inactive, all
	search := c.Query("search")     // search term
	skillFilter := c.Query("skill") // filter by skill

	// Simulate database query
	users := []User{
		{
			ID:        1,
			Name:      "John Doe",
			Email:     "john@example.com",
			Age:       30,
			IsActive:  true,
			CreatedAt: time.Now().Add(-48 * time.Hour),
			Profile: &Profile{
				Skills:   []string{"Go", "Docker"},
				Location: "San Francisco",
			},
		},
		{
			ID:        2,
			Name:      "Jane Smith",
			Email:     "jane@example.com",
			Age:       28,
			IsActive:  true,
			CreatedAt: time.Now().Add(-24 * time.Hour),
			Profile: &Profile{
				Skills:   []string{"Python", "React"},
				Location: "New York",
			},
		},
	}

	// Apply filters (simplified)
	var filteredUsers []User
	for _, user := range users {
		include := true

		if status != "" && status != "all" {
			if status == "active" && !user.IsActive {
				include = false
			}
			if status == "inactive" && user.IsActive {
				include = false
			}
		}

		if search != "" {
			if !contains(user.Name, search) && !contains(user.Email, search) {
				include = false
			}
		}

		if skillFilter != "" && user.Profile != nil {
			hasSkill := false
			for _, skill := range user.Profile.Skills {
				if contains(skill, skillFilter) {
					hasSkill = true
					break
				}
			}
			if !hasSkill {
				include = false
			}
		}

		if include {
			filteredUsers = append(filteredUsers, user)
		}
	}

	total := len(filteredUsers)
	totalPages := (total + pageSize - 1) / pageSize

	// Simulate pagination
	start := (page - 1) * pageSize
	end := start + pageSize
	if start >= total {
		filteredUsers = []User{}
	} else {
		if end > total {
			end = total
		}
		filteredUsers = filteredUsers[start:end]
	}

	response := PaginatedUsersResponse{
		Users:      filteredUsers,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}

	c.JSON(200, response)
}

// Standard HTTP handler for framework-agnostic example
func handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		if r.URL.Path == "/users/" {
			// List users
			users := []User{
				{ID: 1, Name: "John", Email: "john@example.com", Age: 30, IsActive: true},
				{ID: 2, Name: "Jane", Email: "jane@example.com", Age: 25, IsActive: true},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(users)
		} else {
			// Get specific user
			w.Header().Set("Content-Type", "application/json")
			user := User{ID: 1, Name: "John", Email: "john@example.com", Age: 30, IsActive: true}
			json.NewEncoder(w).Encode(user)
		}
	case "POST":
		// Create user
		var req CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		user := User{
			ID:        42,
			Name:      req.Name,
			Email:     req.Email,
			Age:       req.Age,
			IsActive:  true,
			CreatedAt: time.Now(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(user)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Health check endpoint
func healthCheck(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Example 4: Advanced Configuration with Custom Types
func ExampleAdvancedConfiguration() {
	docs := autodocs.New()

	// Rich configuration
	docs.WithConfig(autodocs.Config{
		Title:          "Enterprise User Management API",
		Version:        "3.0.0",
		Description:    "A production-ready user management system with comprehensive features including authentication, authorization, user profiles, and administrative controls.",
		TermsOfService: "https://example.com/terms",
		Contact: &autodocs.Contact{
			Name:  "API Support Team",
			URL:   "https://example.com/support",
			Email: "api-support@example.com",
		},
		License: &autodocs.License{
			Name: "MIT License",
			URL:  "https://opensource.org/licenses/MIT",
		},
		Servers: []autodocs.Server{
			{
				URL:         "https://api.example.com/v3",
				Description: "Production server",
			},
			{
				URL:         "https://staging-api.example.com/v3",
				Description: "Staging server for testing",
			},
			{
				URL:         "http://localhost:8080/v3",
				Description: "Local development server",
			},
		},
		DocsPath:      "/documentation",
		RedocPath:     "/api-docs",
		SpecPath:      "/api/openapi.json",
		DisableTryOut: false,
		Theme:         autodocs.ThemeDark,
		Security: []autodocs.SecurityScheme{
			{
				Type:         "http",
				Scheme:       "bearer",
				BearerFormat: "JWT",
			},
			{
				Type: "apiKey",
				In:   "header",
				Name: "X-API-Key",
			},
			{
				Type: "oauth2",
				Flows: map[string]string{
					"authorizationCode": "https://auth.example.com/oauth/authorize",
					"tokenUrl":          "https://auth.example.com/oauth/token",
				},
			},
		},
	})

	// Register complex routes with rich metadata
	docs.RegisterRoute("GET", "/users/{id}/profile", GetUserProfile,
		autodocs.WithSummary("Get detailed user profile"),
		autodocs.WithDescription("Retrieves comprehensive user profile information including personal details, preferences, activity history, and associated data. Requires appropriate permissions to access sensitive information."),
		autodocs.WithTags("users", "profiles", "personal-data"),
		autodocs.WithResponseType(200, reflect.TypeOf(User{})),
		autodocs.WithResponseType(403, reflect.TypeOf(ErrorResponse{})),
		autodocs.WithResponseType(404, reflect.TypeOf(ErrorResponse{})),
		autodocs.WithSecurity("bearerAuth", "oauth2"),
	)

	log.Println("🏢 Enterprise API documentation configured")
}

// GetUserProfile demonstrates complex handler with multiple response types
func GetUserProfile(c *gin.Context) {
	// Extract user ID from path
	userID := c.Param("id")

	// Extract authentication info (simulated)
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(401, ErrorResponse{
			Error: "Authentication required",
			Code:  401,
		})
		return
	}

	// Simulate permission check
	if userID == "restricted" {
		c.JSON(403, ErrorResponse{
			Error:   "Access denied",
			Code:    403,
			Details: "You don't have permission to access this user's profile",
		})
		return
	}

	// Simulate user not found
	if userID == "999" {
		c.JSON(404, ErrorResponse{
			Error: "User not found",
			Code:  404,
		})
		return
	}

	// Return full user profile
	user := User{
		ID:        1,
		Name:      "John Doe",
		Email:     "john.doe@example.com",
		Age:       30,
		IsActive:  true,
		CreatedAt: time.Now().Add(-365 * 24 * time.Hour),
		Profile: &Profile{
			Bio:      "Senior Software Engineer with 8+ years of experience in Go, microservices, and cloud architecture.",
			Skills:   []string{"Go", "Docker", "Kubernetes", "AWS", "PostgreSQL", "Redis"},
			Location: "San Francisco, CA",
			Website:  "https://johndoe.dev",
			SocialLinks: map[string]string{
				"twitter":  "@johndoe",
				"github":   "johndoe",
				"linkedin": "johndoe",
			},
		},
	}

	c.JSON(200, user)
}

// Example 5: Production Deployment Pattern
func ExampleProductionDeployment() {
	// Production-ready setup with environment configuration
	r := gin.New()

	// Add production middleware
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	// API versioning
	v1 := r.Group("/api/v1")
	{
		v1.GET("/users/:id", GetUser)
		v1.POST("/users", CreateUser)
		v1.PUT("/users/:id", UpdateUser)
		v1.DELETE("/users/:id", DeleteUser)
		v1.GET("/users", ListUsers)
	}

	// Documentation setup with production configuration
	docs := autodocs.QuickSetup(r,
		autodocs.WithTitle("Production API"),
		autodocs.WithVersion("1.0.0"),
		//autodocs.WithDescription("Production-ready API with comprehensive documentation"),
		autodocs.WithServer("https://api.production.com", "Production"),
		autodocs.WithServer("https://api.staging.com", "Staging"),
		autodocs.WithBearerAuth(),
		autodocs.WithAPIKeyAuth("X-API-Key", "header"),
	)

	// Documentation endpoints (can be behind authentication in production)
	r.Any("/docs/*any", gin.WrapH(docs))
	r.Any("/redoc/*any", gin.WrapH(docs))
	r.GET("/openapi.json", gin.WrapH(docs))

	// Health check (important for production)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":    "healthy",
			"timestamp": time.Now(),
			"version":   "1.0.0",
		})
	})

	log.Println("🚀 Production server ready")
	log.Println("📚 Documentation: /docs")
	log.Println("🏥 Health check: /health")

	// In production, you might want to conditionally enable docs
	// based on environment variables
	if gin.Mode() != gin.ReleaseMode {
		log.Println("📖 API Docs: http://localhost:8080/docs")
	}

	r.Run(":8080")
}

// Main function showing different usage patterns
func main() {
	log.Println("🔧 AutoDocs Library Examples")
	log.Println("Choose an example to run:")
	log.Println("1. Gin Zero Config (recommended)")
	log.Println("2. Manual Registration")
	log.Println("3. Standard HTTP")
	log.Println("4. Advanced Configuration")
	log.Println("5. Production Deployment")

	// For demonstration, run the zero-config example
	// In practice, you'd choose based on your needs
	ExampleGinZeroConfig()
}
