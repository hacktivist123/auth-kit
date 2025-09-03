package authkit

import (
	"database/sql/driver"
	"encoding/json"
	"time"
)

type User struct {
	ID        int64        `json:"id" db:"id"`
	Username  string       `json:"username" db:"username"`
	Email     string       `json:"email" db:"email"`
	Password  string       `json:"-" db:"password_hash"`
	IsActive  bool         `json:"is_active" db:"is_active"`
	CreatedAt time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt time.Time    `json:"updated_at" db:"updated_at"`
	Metadata  UserMetadata `json:"metadata" db:"metadata"`
}

// UserMetadata allows projects to store custom user data without changing the schema
type UserMetadata map[string]interface{}

type Session struct {
	ID        int64     `json:"id" db:"id"`
	UserID    int64     `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	IPAddress string    `json:"ip_address" db:"ip_address"`
	UserAgent string    `json:"user_agent" db:"user_agent"`
}

// Value implements the driver.Valuer interface. This converts the Map to a JSON string for storage in the database
func (u UserMetadata) Value() (driver.Value, error) {
	return json.Marshal(u)
}

// Scan implements the sql.Scanner interface. This converts the JSON from the database back to a map
func (u *UserMetadata) Scan(value interface{}) error {
	if value == nil {
		*u = make(UserMetadata)
		return nil
	}
	return json.Unmarshal(value.([]byte), u)
}
