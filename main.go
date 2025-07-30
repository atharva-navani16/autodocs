package main

import (
	"encoding/json"
	"log"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// Complex domain models
type User struct {
	ID        int       `json:"id" example:"1"`
	Name      string    `json:"name" example:"John Doe"`
	Email     string    `json:"email" example:"john@example.com"`
	Role      string    `json:"role" example:"admin"`
	IsActive  bool      `json:"is_active" example:"true"`
	CreatedAt time.Time `json:"created_at" example:"2024-01-15T10:30:00Z"`
	UpdatedAt time.Time `json:"updated_at" example:"2024-01-20T15:45:00Z"`
	Profile   *Profile  `json:"profile,omitempty"`
	Posts     []Post    `json:"posts,omitempty"`
}

type Profile struct {
	ID       int      `json:"id" example:"1"`
	UserID   int      `json:"user_id" example:"1"`
	Bio      string   `json:"bio" example:"Software engineer passionate about Go"`
	Avatar   string   `json:"avatar" example:"https://example.com/avatar.jpg"`
	Skills   []string `json:"skills" example:"Go,Docker,Kubernetes"`
	Location string   `json:"location" example:"San Francisco, CA"`
	Website  string   `json:"website" example:"https://johndoe.dev"`
	Social   Social   `json:"social"`
	Settings Settings `json:"settings"`
}

type Social struct {
	Twitter   string `json:"twitter,omitempty" example:"@johndoe"`
	GitHub    string `json:"github,omitempty" example:"johndoe"`
	LinkedIn  string `json:"linkedin,omitempty" example:"johndoe"`
	Instagram string `json:"instagram,omitempty" example:"@johndoe"`
}

type Settings struct {
	EmailNotifications bool   `json:"email_notifications" example:"true"`
	PublicProfile      bool   `json:"public_profile" example:"true"`
	Theme              string `json:"theme" example:"dark"`
	Language           string `json:"language" example:"en"`
}

type Post struct {
	ID        int       `json:"id" example:"1"`
	UserID    int       `json:"user_id" example:"1"`
	Title     string    `json:"title" example:"Getting Started with Go"`
	Content   string    `json:"content" example:"Go is an amazing programming language..."`
	Status    string    `json:"status" example:"published"`
	Tags      []string  `json:"tags" example:"go,programming,tutorial"`
	Views     int       `json:"views" example:"1250"`
	Likes     int       `json:"likes" example:"45"`
	CreatedAt time.Time `json:"created_at" example:"2024-01-15T10:30:00Z"`
	UpdatedAt time.Time `json:"updated_at" example:"2024-01-20T15:45:00Z"`
	Author    *User     `json:"author,omitempty"`
	Comments  []Comment `json:"comments,omitempty"`
}

type Comment struct {
	ID        int       `json:"id" example:"1"`
	PostID    int       `json:"post_id" example:"1"`
	UserID    int       `json:"user_id" example:"2"`
	Content   string    `json:"content" example:"Great article! Thanks for sharing."`
	CreatedAt time.Time `json:"created_at" example:"2024-01-16T09:15:00Z"`
	UpdatedAt time.Time `json:"updated_at" example:"2024-01-16T09:15:00Z"`
	Author    *User     `json:"author,omitempty"`
}

// Request/Response DTOs
type CreateUserRequest struct {
	Name     string `json:"name" example:"Jane Smith"`
	Email    string `json:"email" example:"jane@example.com"`
	Role     string `json:"role" example:"user"`
	Password string `json:"password" example:"securepassword123"`
}

type UpdateUserRequest struct {
	Name     *string `json:"name,omitempty" example:"Jane Doe"`
	Email    *string `json:"email,omitempty" example:"jane.doe@example.com"`
	Role     *string `json:"role,omitempty" example:"admin"`
	IsActive *bool   `json:"is_active,omitempty" example:"false"`
}

type CreatePostRequest struct {
	Title   string   `json:"title" example:"My New Blog Post"`
	Content string   `json:"content" example:"This is the content of my blog post..."`
	Status  string   `json:"status" example:"draft"`
	Tags    []string `json:"tags" example:"go,web,api"`
}

type UpdatePostRequest struct {
	Title   *string  `json:"title,omitempty" example:"Updated Blog Post Title"`
	Content *string  `json:"content,omitempty" example:"Updated content..."`
	Status  *string  `json:"status,omitempty" example:"published"`
	Tags    []string `json:"tags,omitempty" example:"go,web,api,updated"`
}

type CreateCommentRequest struct {
	Content string `json:"content" example:"This is a great post!"`
}

type UpdateProfileRequest struct {
	Bio      *string   `json:"bio,omitempty" example:"Updated bio"`
	Avatar   *string   `json:"avatar,omitempty" example:"https://example.com/new-avatar.jpg"`
	Skills   []string  `json:"skills,omitempty" example:"Go,Python,React"`
	Location *string   `json:"location,omitempty" example:"New York, NY"`
	Website  *string   `json:"website,omitempty" example:"https://newwebsite.com"`
	Social   *Social   `json:"social,omitempty"`
	Settings *Settings `json:"settings,omitempty"`
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Total      int         `json:"total" example:"150"`
	Page       int         `json:"page" example:"1"`
	PageSize   int         `json:"page_size" example:"20"`
	TotalPages int         `json:"total_pages" example:"8"`
	HasNext    bool        `json:"has_next" example:"true"`
	HasPrev    bool        `json:"has_prev" example:"false"`
}

type ErrorResponse struct {
	Error      string            `json:"error" example:"User not found"`
	Code       int               `json:"code" example:"404"`
	Details    string            `json:"details,omitempty" example:"User with ID 123 does not exist"`
	Timestamp  time.Time         `json:"timestamp" example:"2024-01-15T10:30:00Z"`
	Path       string            `json:"path" example:"/users/123"`
	Validation map[string]string `json:"validation,omitempty"`
}

type AuthResponse struct {
	Token     string    `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	User      User      `json:"user"`
	ExpiresAt time.Time `json:"expires_at" example:"2024-01-15T10:30:00Z"`
}

type LoginRequest struct {
	Email    string `json:"email" example:"john@example.com"`
	Password string `json:"password" example:"password123"`
}

// Mock data store
var (
	users    = make(map[int]*User)
	posts    = make(map[int]*Post)
	comments = make(map[int]*Comment)
	profiles = make(map[int]*Profile)
	nextID   = 1
)

func main() {
	// Initialize mock data
	initMockData()

	r := gin.Default()

	// Add CORS middleware
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Authentication routes
	auth := r.Group("/auth")
	{
		auth.POST("/login", Login)
		auth.POST("/register", Register)
		auth.POST("/logout", Logout)
		auth.GET("/me", GetCurrentUser)
	}

	// User management routes
	users := r.Group("/users")
	{
		users.GET("", ListUsers)                     // GET /users?page=1&limit=20&role=admin&active=true
		users.POST("", CreateUser)                   // POST /users
		users.GET("/:id", GetUser)                   // GET /users/123
		users.PUT("/:id", UpdateUser)                // PUT /users/123
		users.PATCH("/:id", PatchUser)               // PATCH /users/123
		users.DELETE("/:id", DeleteUser)             // DELETE /users/123
		users.GET("/:id/posts", GetUserPosts)        // GET /users/123/posts
		users.GET("/:id/profile", GetUserProfile)    // GET /users/123/profile
		users.PUT("/:id/profile", UpdateUserProfile) // PUT /users/123/profile
	}

	// Post management routes
	posts := r.Group("/posts")
	{
		posts.GET("", ListPosts)                    // GET /posts?page=1&limit=10&status=published&tag=go
		posts.POST("", CreatePost)                  // POST /posts
		posts.GET("/:id", GetPost)                  // GET /posts/123
		posts.PUT("/:id", UpdatePost)               // PUT /posts/123
		posts.PATCH("/:id", PatchPost)              // PATCH /posts/123
		posts.DELETE("/:id", DeletePost)            // DELETE /posts/123
		posts.POST("/:id/like", LikePost)           // POST /posts/123/like
		posts.DELETE("/:id/like", UnlikePost)       // DELETE /posts/123/like
		posts.GET("/:id/comments", GetPostComments) // GET /posts/123/comments
		posts.POST("/:id/comments", CreateComment)  // POST /posts/123/comments
	}

	// Comment management routes
	comments := r.Group("/comments")
	{
		comments.GET("/:id", GetComment)       // GET /comments/123
		comments.PUT("/:id", UpdateComment)    // PUT /comments/123
		comments.PATCH("/:id", PatchComment)   // PATCH /comments/123
		comments.DELETE("/:id", DeleteComment) // DELETE /comments/123
	}

	// Analytics and stats routes
	stats := r.Group("/stats")
	{
		stats.GET("/dashboard", GetDashboardStats)   // GET /stats/dashboard
		stats.GET("/users", GetUserStats)            // GET /stats/users
		stats.GET("/posts", GetPostStats)            // GET /stats/posts
		stats.GET("/engagement", GetEngagementStats) // GET /stats/engagement
	}

	// Search routes
	search := r.Group("/search")
	{
		search.GET("/users", SearchUsers)   // GET /search/users?q=john&limit=10
		search.GET("/posts", SearchPosts)   // GET /search/posts?q=golang&limit=10
		search.GET("/global", GlobalSearch) // GET /search/global?q=api&type=all
	}

	// Admin routes
	admin := r.Group("/admin")
	{
		admin.GET("/users", AdminListUsers)                   // GET /admin/users
		admin.POST("/users/:id/activate", ActivateUser)       // POST /admin/users/123/activate
		admin.POST("/users/:id/deactivate", DeactivateUser)   // POST /admin/users/123/deactivate
		admin.GET("/posts/moderation", GetPostsForModeration) // GET /admin/posts/moderation
		admin.POST("/posts/:id/approve", ApprovePost)         // POST /admin/posts/123/approve
		admin.POST("/posts/:id/reject", RejectPost)           // POST /admin/posts/123/reject
	}

	// Health and utility routes
	r.GET("/health", HealthCheck)
	r.GET("/version", GetVersion)
	r.GET("/metrics", GetMetrics)

	// Documentation routes
	r.GET("/docs", ServeDocs)
	r.GET("/openapi.json", ServeOpenAPISpec)

	log.Println("🚀 Complex API Server running on :8080")
	log.Println("📚 API Documentation: http://localhost:8080/docs")
	log.Println("📋 OpenAPI Spec: http://localhost:8080/openapi.json")
	log.Println("🏥 Health Check: http://localhost:8080/health")
	log.Println("🧪 Test Endpoints:")
	log.Println("   GET  /users")
	log.Println("   POST /users")
	log.Println("   GET  /users/1")
	log.Println("   GET  /posts")
	log.Println("   POST /posts")
	log.Println("   GET  /posts/1")

	r.Run(":8080")
}

// Initialize mock data
func initMockData() {
	// Create mock users
	user1 := &User{
		ID:        1,
		Name:      "John Doe",
		Email:     "john@example.com",
		Role:      "admin",
		IsActive:  true,
		CreatedAt: time.Now().Add(-72 * time.Hour),
		UpdatedAt: time.Now().Add(-24 * time.Hour),
	}

	user2 := &User{
		ID:        2,
		Name:      "Jane Smith",
		Email:     "jane@example.com",
		Role:      "user",
		IsActive:  true,
		CreatedAt: time.Now().Add(-48 * time.Hour),
		UpdatedAt: time.Now().Add(-12 * time.Hour),
	}

	users[1] = user1
	users[2] = user2

	// Create mock profiles
	profile1 := &Profile{
		ID:       1,
		UserID:   1,
		Bio:      "Full-stack developer with 8+ years of experience",
		Avatar:   "https://example.com/avatars/john.jpg",
		Skills:   []string{"Go", "JavaScript", "Docker", "Kubernetes"},
		Location: "San Francisco, CA",
		Website:  "https://johndoe.dev",
		Social: Social{
			Twitter:  "@johndoe",
			GitHub:   "johndoe",
			LinkedIn: "johndoe",
		},
		Settings: Settings{
			EmailNotifications: true,
			PublicProfile:      true,
			Theme:              "dark",
			Language:           "en",
		},
	}

	profiles[1] = profile1
	user1.Profile = profile1

	// Create mock posts
	post1 := &Post{
		ID:        1,
		UserID:    1,
		Title:     "Getting Started with Go",
		Content:   "Go is an amazing programming language that makes it easy to build simple, reliable, and efficient software...",
		Status:    "published",
		Tags:      []string{"go", "programming", "tutorial"},
		Views:     1250,
		Likes:     45,
		CreatedAt: time.Now().Add(-24 * time.Hour),
		UpdatedAt: time.Now().Add(-12 * time.Hour),
		Author:    user1,
	}

	posts[1] = post1

	// Create mock comments
	comment1 := &Comment{
		ID:        1,
		PostID:    1,
		UserID:    2,
		Content:   "Great article! Thanks for sharing this comprehensive guide.",
		CreatedAt: time.Now().Add(-6 * time.Hour),
		UpdatedAt: time.Now().Add(-6 * time.Hour),
		Author:    user2,
	}

	comments[1] = comment1
	post1.Comments = []Comment{*comment1}

	nextID = 3
}

// Authentication handlers
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{
			Error:     "Invalid request body",
			Code:      400,
			Details:   err.Error(),
			Timestamp: time.Now(),
			Path:      c.Request.URL.Path,
		})
		return
	}

	// Mock authentication
	if req.Email == "john@example.com" && req.Password == "password123" {
		user := users[1]
		c.JSON(200, AuthResponse{
			Token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
			User:      *user,
			ExpiresAt: time.Now().Add(24 * time.Hour),
		})
		return
	}

	c.JSON(401, ErrorResponse{
		Error:     "Invalid credentials",
		Code:      401,
		Timestamp: time.Now(),
		Path:      c.Request.URL.Path,
	})
}

func Register(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{
			Error:     "Invalid request body",
			Code:      400,
			Details:   err.Error(),
			Timestamp: time.Now(),
			Path:      c.Request.URL.Path,
		})
		return
	}

	// Create new user
	user := &User{
		ID:        nextID,
		Name:      req.Name,
		Email:     req.Email,
		Role:      req.Role,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	users[nextID] = user
	nextID++

	c.JSON(201, AuthResponse{
		Token:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
		User:      *user,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})
}

func Logout(c *gin.Context) {
	c.JSON(200, gin.H{"message": "Logged out successfully"})
}

func GetCurrentUser(c *gin.Context) {
	// Mock current user
	user := users[1]
	c.JSON(200, user)
}

// User management handlers
func ListUsers(c *gin.Context) {
	page := getIntParam(c, "page", 1)
	limit := getIntParam(c, "limit", 20)
	role := c.Query("role")
	active := c.Query("active")

	var userList []*User
	for _, user := range users {
		include := true

		if role != "" && user.Role != role {
			include = false
		}

		if active != "" {
			isActive := active == "true"
			if user.IsActive != isActive {
				include = false
			}
		}

		if include {
			userList = append(userList, user)
		}
	}

	total := len(userList)
	totalPages := (total + limit - 1) / limit

	// Simple pagination
	start := (page - 1) * limit
	end := start + limit
	if start >= total {
		userList = []*User{}
	} else {
		if end > total {
			end = total
		}
		userList = userList[start:end]
	}

	response := PaginatedResponse{
		Data:       userList,
		Total:      total,
		Page:       page,
		PageSize:   limit,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}

	c.JSON(200, response)
}

func CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{
			Error:     "Invalid request body",
			Code:      400,
			Details:   err.Error(),
			Timestamp: time.Now(),
			Path:      c.Request.URL.Path,
		})
		return
	}

	user := &User{
		ID:        nextID,
		Name:      req.Name,
		Email:     req.Email,
		Role:      req.Role,
		IsActive:  true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	users[nextID] = user
	nextID++

	c.JSON(201, user)
}

func GetUser(c *gin.Context) {
	id := getIntParam(c, "id", 0)
	if id == 0 {
		c.JSON(400, ErrorResponse{
			Error:     "Invalid user ID",
			Code:      400,
			Timestamp: time.Now(),
			Path:      c.Request.URL.Path,
		})
		return
	}

	user, exists := users[id]
	if !exists {
		c.JSON(404, ErrorResponse{
			Error:     "User not found",
			Code:      404,
			Details:   "User with the specified ID does not exist",
			Timestamp: time.Now(),
			Path:      c.Request.URL.Path,
		})
		return
	}

	c.JSON(200, user)
}

func UpdateUser(c *gin.Context) {
	id := getIntParam(c, "id", 0)
	user, exists := users[id]
	if !exists {
		c.JSON(404, ErrorResponse{
			Error:     "User not found",
			Code:      404,
			Timestamp: time.Now(),
			Path:      c.Request.URL.Path,
		})
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{
			Error:     "Invalid request body",
			Code:      400,
			Details:   err.Error(),
			Timestamp: time.Now(),
			Path:      c.Request.URL.Path,
		})
		return
	}

	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Email != nil {
		user.Email = *req.Email
	}
	if req.Role != nil {
		user.Role = *req.Role
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	user.UpdatedAt = time.Now()

	c.JSON(200, user)
}

func PatchUser(c *gin.Context) {
	// Same as UpdateUser for this example
	UpdateUser(c)
}

func DeleteUser(c *gin.Context) {
	id := getIntParam(c, "id", 0)
	if _, exists := users[id]; !exists {
		c.JSON(404, ErrorResponse{
			Error:     "User not found",
			Code:      404,
			Timestamp: time.Now(),
			Path:      c.Request.URL.Path,
		})
		return
	}

	delete(users, id)
	c.Status(204)
}

// Post management handlers (simplified for space)
func ListPosts(c *gin.Context) {
	var postList []*Post
	for _, post := range posts {
		postList = append(postList, post)
	}

	c.JSON(200, PaginatedResponse{
		Data:       postList,
		Total:      len(postList),
		Page:       1,
		PageSize:   20,
		TotalPages: 1,
		HasNext:    false,
		HasPrev:    false,
	})
}

func CreatePost(c *gin.Context) {
	var req CreatePostRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{
			Error:     "Invalid request body",
			Code:      400,
			Details:   err.Error(),
			Timestamp: time.Now(),
			Path:      c.Request.URL.Path,
		})
		return
	}

	post := &Post{
		ID:        nextID,
		UserID:    1, // Mock current user
		Title:     req.Title,
		Content:   req.Content,
		Status:    req.Status,
		Tags:      req.Tags,
		Views:     0,
		Likes:     0,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Author:    users[1],
	}

	posts[nextID] = post
	nextID++

	c.JSON(201, post)
}

func GetPost(c *gin.Context) {
	id := getIntParam(c, "id", 0)
	post, exists := posts[id]
	if !exists {
		c.JSON(404, ErrorResponse{
			Error:     "Post not found",
			Code:      404,
			Timestamp: time.Now(),
			Path:      c.Request.URL.Path,
		})
		return
	}

	c.JSON(200, post)
}

// Utility handlers
func HealthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "1.0.0",
		"uptime":    "2h 15m 30s",
		"database":  "connected",
		"cache":     "connected",
	})
}

func GetVersion(c *gin.Context) {
	c.JSON(200, gin.H{
		"version":    "1.0.0",
		"build":      "abc123",
		"go_version": "1.21.0",
		"built_at":   "2024-01-15T10:30:00Z",
	})
}

// Helper functions
func getIntParam(c *gin.Context, key string, defaultValue int) int {
	if value := c.Query(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	if value := c.Param(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// Simplified handlers for other endpoints (to keep file manageable)
func UpdatePost(c *gin.Context)            { c.JSON(200, gin.H{"message": "Post updated"}) }
func PatchPost(c *gin.Context)             { c.JSON(200, gin.H{"message": "Post patched"}) }
func DeletePost(c *gin.Context)            { c.Status(204) }
func LikePost(c *gin.Context)              { c.JSON(200, gin.H{"message": "Post liked"}) }
func UnlikePost(c *gin.Context)            { c.JSON(200, gin.H{"message": "Post unliked"}) }
func GetPostComments(c *gin.Context)       { c.JSON(200, []Comment{}) }
func CreateComment(c *gin.Context)         { c.JSON(201, gin.H{"message": "Comment created"}) }
func GetComment(c *gin.Context)            { c.JSON(200, gin.H{"message": "Comment retrieved"}) }
func UpdateComment(c *gin.Context)         { c.JSON(200, gin.H{"message": "Comment updated"}) }
func PatchComment(c *gin.Context)          { c.JSON(200, gin.H{"message": "Comment patched"}) }
func DeleteComment(c *gin.Context)         { c.Status(204) }
func GetUserPosts(c *gin.Context)          { c.JSON(200, []Post{}) }
func GetUserProfile(c *gin.Context)        { c.JSON(200, profiles[1]) }
func UpdateUserProfile(c *gin.Context)     { c.JSON(200, gin.H{"message": "Profile updated"}) }
func GetDashboardStats(c *gin.Context)     { c.JSON(200, gin.H{"users": 100, "posts": 250}) }
func GetUserStats(c *gin.Context)          { c.JSON(200, gin.H{"total": 100, "active": 85}) }
func GetPostStats(c *gin.Context)          { c.JSON(200, gin.H{"total": 250, "published": 200}) }
func GetEngagementStats(c *gin.Context)    { c.JSON(200, gin.H{"views": 10000, "likes": 500}) }
func SearchUsers(c *gin.Context)           { c.JSON(200, []User{}) }
func SearchPosts(c *gin.Context)           { c.JSON(200, []Post{}) }
func GlobalSearch(c *gin.Context)          { c.JSON(200, gin.H{"results": []string{}}) }
func AdminListUsers(c *gin.Context)        { c.JSON(200, []User{}) }
func ActivateUser(c *gin.Context)          { c.JSON(200, gin.H{"message": "User activated"}) }
func DeactivateUser(c *gin.Context)        { c.JSON(200, gin.H{"message": "User deactivated"}) }
func GetPostsForModeration(c *gin.Context) { c.JSON(200, []Post{}) }
func ApprovePost(c *gin.Context)           { c.JSON(200, gin.H{"message": "Post approved"}) }
func RejectPost(c *gin.Context)            { c.JSON(200, gin.H{"message": "Post rejected"}) }
func GetMetrics(c *gin.Context)            { c.JSON(200, gin.H{"requests": 1000, "errors": 5}) }

// Documentation endpoints (simplified - would be generated by autodocs library)
func ServeDocs(c *gin.Context) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Complex API Documentation - Swagger UI</title>
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
            url: '/openapi.json',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.presets.standalone
            ],
            plugins: [
                SwaggerUIBundle.plugins.DownloadUrl
            ],
            tryItOutEnabled: true,
            supportedSubmitMethods: ['get', 'post', 'put', 'patch', 'delete', 'head', 'options']
        });
    </script>
</body>
</html>`

	c.Header("Content-Type", "text/html")
	c.String(200, html)
}

func ServeOpenAPISpec(c *gin.Context) {
	spec := map[string]interface{}{
		"openapi": "3.0.3",
		"info": map[string]interface{}{
			"title":       "Complex Blog API",
			"version":     "1.0.0",
			"description": "A comprehensive blog management API with users, posts, comments, and admin features",
			"contact": map[string]interface{}{
				"name":  "API Support",
				"email": "support@example.com",
				"url":   "https://example.com/support",
			},
		},
		"servers": []map[string]interface{}{
			{
				"url":         "http://localhost:8080",
				"description": "Development server",
			},
		},
		"tags": []map[string]interface{}{
			{"name": "auth", "description": "Authentication operations"},
			{"name": "users", "description": "User management"},
			{"name": "posts", "description": "Blog post management"},
			{"name": "comments", "description": "Comment management"},
			{"name": "admin", "description": "Administrative operations"},
			{"name": "search", "description": "Search operations"},
			{"name": "stats", "description": "Analytics and statistics"},
		},
		"paths": map[string]interface{}{
			// Authentication endpoints
			"/auth/login": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"auth"},
					"summary":     "User login",
					"description": "Authenticate user with email and password",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"$ref": "#/components/schemas/LoginRequest"},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Login successful",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/AuthResponse"},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Invalid credentials",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
					},
				},
			},
			"/auth/register": map[string]interface{}{
				"post": map[string]interface{}{
					"tags":        []string{"auth"},
					"summary":     "User registration",
					"description": "Register a new user account",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"$ref": "#/components/schemas/CreateUserRequest"},
							},
						},
					},
					"responses": map[string]interface{}{
						"201": map[string]interface{}{
							"description": "User registered successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/AuthResponse"},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Invalid request data",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
					},
				},
			},
			"/auth/me": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"auth"},
					"summary":     "Get current user",
					"description": "Get the currently authenticated user's information",
					"security":    []map[string][]string{{"bearerAuth": {}}},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Current user information",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/User"},
								},
							},
						},
						"401": map[string]interface{}{
							"description": "Unauthorized",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
					},
				},
			},
			// User management endpoints
			"/users": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"users"},
					"summary":     "List users",
					"description": "Get a paginated list of users with optional filtering",
					"parameters": []map[string]interface{}{
						{
							"name":        "page",
							"in":          "query",
							"description": "Page number",
							"schema":      map[string]interface{}{"type": "integer", "default": 1},
						},
						{
							"name":        "limit",
							"in":          "query",
							"description": "Items per page",
							"schema":      map[string]interface{}{"type": "integer", "default": 20, "maximum": 100},
						},
						{
							"name":        "role",
							"in":          "query",
							"description": "Filter by user role",
							"schema":      map[string]interface{}{"type": "string", "enum": []string{"admin", "user", "moderator"}},
						},
						{
							"name":        "active",
							"in":          "query",
							"description": "Filter by active status",
							"schema":      map[string]interface{}{"type": "boolean"},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "List of users",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/PaginatedUsersResponse"},
								},
							},
						},
					},
				},
				"post": map[string]interface{}{
					"tags":        []string{"users"},
					"summary":     "Create user",
					"description": "Create a new user account",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"$ref": "#/components/schemas/CreateUserRequest"},
							},
						},
					},
					"responses": map[string]interface{}{
						"201": map[string]interface{}{
							"description": "User created successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/User"},
								},
							},
						},
						"400": map[string]interface{}{
							"description": "Invalid request data",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
					},
				},
			},
			"/users/{id}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"users"},
					"summary":     "Get user by ID",
					"description": "Retrieve a specific user by their ID",
					"parameters": []map[string]interface{}{
						{
							"name":        "id",
							"in":          "path",
							"required":    true,
							"description": "User ID",
							"schema":      map[string]interface{}{"type": "integer"},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "User found",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/User"},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "User not found",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
					},
				},
				"put": map[string]interface{}{
					"tags":        []string{"users"},
					"summary":     "Update user",
					"description": "Update all user fields (full update)",
					"parameters": []map[string]interface{}{
						{
							"name":     "id",
							"in":       "path",
							"required": true,
							"schema":   map[string]interface{}{"type": "integer"},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"$ref": "#/components/schemas/UpdateUserRequest"},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "User updated successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/User"},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "User not found",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
					},
				},
				"patch": map[string]interface{}{
					"tags":        []string{"users"},
					"summary":     "Partially update user",
					"description": "Update specific user fields (partial update)",
					"parameters": []map[string]interface{}{
						{
							"name":     "id",
							"in":       "path",
							"required": true,
							"schema":   map[string]interface{}{"type": "integer"},
						},
					},
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"$ref": "#/components/schemas/UpdateUserRequest"},
							},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "User updated successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/User"},
								},
							},
						},
					},
				},
				"delete": map[string]interface{}{
					"tags":        []string{"users"},
					"summary":     "Delete user",
					"description": "Permanently delete a user account",
					"parameters": []map[string]interface{}{
						{
							"name":     "id",
							"in":       "path",
							"required": true,
							"schema":   map[string]interface{}{"type": "integer"},
						},
					},
					"responses": map[string]interface{}{
						"204": map[string]interface{}{
							"description": "User deleted successfully",
						},
						"404": map[string]interface{}{
							"description": "User not found",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
					},
				},
			},
			// Posts endpoints
			"/posts": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"posts"},
					"summary":     "List posts",
					"description": "Get a paginated list of blog posts",
					"parameters": []map[string]interface{}{
						{
							"name":        "page",
							"in":          "query",
							"description": "Page number",
							"schema":      map[string]interface{}{"type": "integer", "default": 1},
						},
						{
							"name":        "limit",
							"in":          "query",
							"description": "Items per page",
							"schema":      map[string]interface{}{"type": "integer", "default": 10},
						},
						{
							"name":        "status",
							"in":          "query",
							"description": "Filter by post status",
							"schema":      map[string]interface{}{"type": "string", "enum": []string{"published", "draft", "archived"}},
						},
						{
							"name":        "tag",
							"in":          "query",
							"description": "Filter by tag",
							"schema":      map[string]interface{}{"type": "string"},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "List of posts",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/PaginatedPostsResponse"},
								},
							},
						},
					},
				},
				"post": map[string]interface{}{
					"tags":        []string{"posts"},
					"summary":     "Create post",
					"description": "Create a new blog post",
					"requestBody": map[string]interface{}{
						"required": true,
						"content": map[string]interface{}{
							"application/json": map[string]interface{}{
								"schema": map[string]interface{}{"$ref": "#/components/schemas/CreatePostRequest"},
							},
						},
					},
					"responses": map[string]interface{}{
						"201": map[string]interface{}{
							"description": "Post created successfully",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/Post"},
								},
							},
						},
					},
				},
			},
			"/posts/{id}": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"posts"},
					"summary":     "Get post by ID",
					"description": "Retrieve a specific blog post",
					"parameters": []map[string]interface{}{
						{
							"name":     "id",
							"in":       "path",
							"required": true,
							"schema":   map[string]interface{}{"type": "integer"},
						},
					},
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "Post found",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/Post"},
								},
							},
						},
						"404": map[string]interface{}{
							"description": "Post not found",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{"$ref": "#/components/schemas/ErrorResponse"},
								},
							},
						},
					},
				},
			},
			// Health and utility endpoints
			"/health": map[string]interface{}{
				"get": map[string]interface{}{
					"tags":        []string{"system"},
					"summary":     "Health check",
					"description": "Check the health status of the API",
					"responses": map[string]interface{}{
						"200": map[string]interface{}{
							"description": "System is healthy",
							"content": map[string]interface{}{
								"application/json": map[string]interface{}{
									"schema": map[string]interface{}{
										"type": "object",
										"properties": map[string]interface{}{
											"status":    map[string]interface{}{"type": "string", "example": "healthy"},
											"timestamp": map[string]interface{}{"type": "string", "format": "date-time"},
											"version":   map[string]interface{}{"type": "string", "example": "1.0.0"},
											"uptime":    map[string]interface{}{"type": "string", "example": "2h 15m 30s"},
											"database":  map[string]interface{}{"type": "string", "example": "connected"},
											"cache":     map[string]interface{}{"type": "string", "example": "connected"},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"bearerAuth": map[string]interface{}{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
			},
			"schemas": map[string]interface{}{
				"User": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id":         map[string]interface{}{"type": "integer", "example": 1},
						"name":       map[string]interface{}{"type": "string", "example": "John Doe"},
						"email":      map[string]interface{}{"type": "string", "example": "john@example.com"},
						"role":       map[string]interface{}{"type": "string", "example": "admin", "enum": []string{"admin", "user", "moderator"}},
						"is_active":  map[string]interface{}{"type": "boolean", "example": true},
						"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
						"updated_at": map[string]interface{}{"type": "string", "format": "date-time"},
						"profile":    map[string]interface{}{"$ref": "#/components/schemas/Profile"},
						"posts":      map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/components/schemas/Post"}},
					},
					"required": []string{"id", "name", "email", "role", "is_active"},
				},
				"Profile": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id":       map[string]interface{}{"type": "integer"},
						"user_id":  map[string]interface{}{"type": "integer"},
						"bio":      map[string]interface{}{"type": "string", "example": "Software engineer"},
						"avatar":   map[string]interface{}{"type": "string", "example": "https://example.com/avatar.jpg"},
						"skills":   map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "example": []string{"Go", "Docker"}},
						"location": map[string]interface{}{"type": "string", "example": "San Francisco, CA"},
						"website":  map[string]interface{}{"type": "string", "example": "https://johndoe.dev"},
						"social":   map[string]interface{}{"$ref": "#/components/schemas/Social"},
						"settings": map[string]interface{}{"$ref": "#/components/schemas/Settings"},
					},
				},
				"Social": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"twitter":   map[string]interface{}{"type": "string", "example": "@johndoe"},
						"github":    map[string]interface{}{"type": "string", "example": "johndoe"},
						"linkedin":  map[string]interface{}{"type": "string", "example": "johndoe"},
						"instagram": map[string]interface{}{"type": "string", "example": "@johndoe"},
					},
				},
				"Settings": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"email_notifications": map[string]interface{}{"type": "boolean", "example": true},
						"public_profile":      map[string]interface{}{"type": "boolean", "example": true},
						"theme":               map[string]interface{}{"type": "string", "example": "dark", "enum": []string{"light", "dark"}},
						"language":            map[string]interface{}{"type": "string", "example": "en"},
					},
				},
				"Post": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id":         map[string]interface{}{"type": "integer", "example": 1},
						"user_id":    map[string]interface{}{"type": "integer", "example": 1},
						"title":      map[string]interface{}{"type": "string", "example": "Getting Started with Go"},
						"content":    map[string]interface{}{"type": "string", "example": "Go is an amazing programming language..."},
						"status":     map[string]interface{}{"type": "string", "example": "published", "enum": []string{"draft", "published", "archived"}},
						"tags":       map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "example": []string{"go", "programming"}},
						"views":      map[string]interface{}{"type": "integer", "example": 1250},
						"likes":      map[string]interface{}{"type": "integer", "example": 45},
						"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
						"updated_at": map[string]interface{}{"type": "string", "format": "date-time"},
						"author":     map[string]interface{}{"$ref": "#/components/schemas/User"},
						"comments":   map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/components/schemas/Comment"}},
					},
					"required": []string{"id", "user_id", "title", "content", "status"},
				},
				"Comment": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"id":         map[string]interface{}{"type": "integer", "example": 1},
						"post_id":    map[string]interface{}{"type": "integer", "example": 1},
						"user_id":    map[string]interface{}{"type": "integer", "example": 2},
						"content":    map[string]interface{}{"type": "string", "example": "Great article!"},
						"created_at": map[string]interface{}{"type": "string", "format": "date-time"},
						"updated_at": map[string]interface{}{"type": "string", "format": "date-time"},
						"author":     map[string]interface{}{"$ref": "#/components/schemas/User"},
					},
					"required": []string{"id", "post_id", "user_id", "content"},
				},
				"CreateUserRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"name":     map[string]interface{}{"type": "string", "example": "Jane Smith"},
						"email":    map[string]interface{}{"type": "string", "example": "jane@example.com"},
						"role":     map[string]interface{}{"type": "string", "example": "user"},
						"password": map[string]interface{}{"type": "string", "example": "securepassword123"},
					},
					"required": []string{"name", "email", "password"},
				},
				"UpdateUserRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"name":      map[string]interface{}{"type": "string", "example": "Jane Doe"},
						"email":     map[string]interface{}{"type": "string", "example": "jane.doe@example.com"},
						"role":      map[string]interface{}{"type": "string", "example": "admin"},
						"is_active": map[string]interface{}{"type": "boolean", "example": false},
					},
				},
				"CreatePostRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"title":   map[string]interface{}{"type": "string", "example": "My New Blog Post"},
						"content": map[string]interface{}{"type": "string", "example": "This is the content..."},
						"status":  map[string]interface{}{"type": "string", "example": "draft"},
						"tags":    map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}, "example": []string{"go", "web"}},
					},
					"required": []string{"title", "content"},
				},
				"LoginRequest": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"email":    map[string]interface{}{"type": "string", "example": "john@example.com"},
						"password": map[string]interface{}{"type": "string", "example": "password123"},
					},
					"required": []string{"email", "password"},
				},
				"AuthResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"token":      map[string]interface{}{"type": "string", "example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."},
						"user":       map[string]interface{}{"$ref": "#/components/schemas/User"},
						"expires_at": map[string]interface{}{"type": "string", "format": "date-time"},
					},
					"required": []string{"token", "user", "expires_at"},
				},
				"PaginatedUsersResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"data":        map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/components/schemas/User"}},
						"total":       map[string]interface{}{"type": "integer", "example": 150},
						"page":        map[string]interface{}{"type": "integer", "example": 1},
						"page_size":   map[string]interface{}{"type": "integer", "example": 20},
						"total_pages": map[string]interface{}{"type": "integer", "example": 8},
						"has_next":    map[string]interface{}{"type": "boolean", "example": true},
						"has_prev":    map[string]interface{}{"type": "boolean", "example": false},
					},
				},
				"PaginatedPostsResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"data":        map[string]interface{}{"type": "array", "items": map[string]interface{}{"$ref": "#/components/schemas/Post"}},
						"total":       map[string]interface{}{"type": "integer", "example": 250},
						"page":        map[string]interface{}{"type": "integer", "example": 1},
						"page_size":   map[string]interface{}{"type": "integer", "example": 10},
						"total_pages": map[string]interface{}{"type": "integer", "example": 25},
						"has_next":    map[string]interface{}{"type": "boolean", "example": true},
						"has_prev":    map[string]interface{}{"type": "boolean", "example": false},
					},
				},
				"ErrorResponse": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"error":      map[string]interface{}{"type": "string", "example": "User not found"},
						"code":       map[string]interface{}{"type": "integer", "example": 404},
						"details":    map[string]interface{}{"type": "string", "example": "User with ID 123 does not exist"},
						"timestamp":  map[string]interface{}{"type": "string", "format": "date-time"},
						"path":       map[string]interface{}{"type": "string", "example": "/users/123"},
						"validation": map[string]interface{}{"type": "object", "additionalProperties": map[string]interface{}{"type": "string"}},
					},
					"required": []string{"error", "code", "timestamp", "path"},
				},
			},
		},
	}

	c.Header("Content-Type", "application/json")
	c.Header("Access-Control-Allow-Origin", "*")

	if err := json.NewEncoder(c.Writer).Encode(spec); err != nil {
		c.JSON(500, ErrorResponse{
			Error:     "Failed to encode OpenAPI spec",
			Code:      500,
			Timestamp: time.Now(),
			Path:      c.Request.URL.Path,
		})
	}
}
