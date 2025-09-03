package authkit

import (
	"database/sql"
	"embed"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql" // MySQL driver
	_ "github.com/lib/pq"              // PostgreSQL driver
	"golang.org/x/crypto/bcrypt"
)

// Embed migration files directly in binary. See https://oscarforner.com/blog/2023-10-10-go-embed-for-migrations/
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

type DatabaseConfig struct {
	Driver   string
	Host     string
	Port     int
	Username string
	Password string
	Database string
	SSLMode  string
}

func connectionString(config *DatabaseConfig) string {
	switch config.Driver {
	case "postgres":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s", config.Host, config.Port, config.Username, config.Password, config.Database, config.SSLMode)
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true", config.Username, config.Password, config.Host, config.Port, config.Database)
	default:
		panic(fmt.Sprintf("unsupported driver: %s", config.Driver))
	}
}

// GetUserByUsername finds a user by their username
func (a *AuthManager) GetUserByUsername(username string) (*User, error) {
	user := &User{}

	// Use parameterized queries to prevent SQL injection
	query := `SELECT id, username, email, password_hash, created_at, updated_at, is_active, metadata 
						FROM users WHERE username = $1 AND is_active = true`

	err := a.db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password,
		&user.CreatedAt, &user.UpdatedAt, &user.IsActive, &user.Metadata,
	)

	// Handle the "no results" case gracefully
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}

	return user, err
}

func (a *AuthManager) CreateUser(username, email, password string) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := &User{
		Username:  username,
		Email:     email,
		Password:  string(hashedPassword), // store the hashed password
		IsActive:  true,
		UpdatedAt: time.Now(),
	}

	query := `INSERT INTO users (username, email, password_hash, is_active, metadata)
						VALUES ($1, $2, $3, $4, $5) RETURNING id, created_at, updated_at`

	err = a.db.QueryRow(query, user.Username, user.Email, user.Password, user.IsActive, user.Metadata).Scan(
		&user.ID, &user.CreatedAt, &user.UpdatedAt)

	return user, err

}
