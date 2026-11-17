package builtin

import (
	"strings"
	"testing"

	"github.com/Voskan/codexsentinel/v2/analyzer/testutil"
)

const boplaModel = `package model

import "time"

type User struct {
	ID           int64  ` + "`json:\"id\" gorm:\"primaryKey\"`" + `
	Email        string ` + "`json:\"email\"`" + `
	PasswordHash string ` + "`json:\"password_hash\"`" + `
	IsAdmin      bool   ` + "`json:\"is_admin\"`" + `
	CreatedAt    time.Time
}

type SafeUser struct {
	ID           int64  ` + "`json:\"id\" gorm:\"primaryKey\"`" + `
	Email        string ` + "`json:\"email\"`" + `
	PasswordHash string ` + "`json:\"-\"`" + `
	IsAdmin      bool   ` + "`json:\"-\"`" + `
	Role         string ` + "`json:\"role\" gorm:\"<-:false\"`" + `
}

type Account struct {
	Owner   User
	Balance int64
}

type Profile struct {
	Name      string
	Salt      string ` + "`json:\"-,\"`" + `
	TwoFactor bool
}

type Custom struct {
	PasswordHash string
}

func (Custom) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
`

func boplaFiles(app string) map[string]string {
	return map[string]string{
		"go.mod":         "module example.com/fixture\n\ngo 1.24\n",
		"model/model.go": boplaModel,
		"app/app.go":     app,
	}
}

func TestAPIBOPLADataExposure(t *testing.T) {
	t.Parallel()
	issues := testutil.RunRulesOnFiles(t, boplaFiles(`package app

import (
	"encoding/json"
	"net/http"

	"example.com/fixture/model"
)

type UserResponseDTO struct {
	ID    int64  `+"`json:\"id\"`"+`
	Email string `+"`json:\"email\"`"+`
}

type TokenResponse struct {
	AccessToken  string `+"`json:\"access_token\"`"+`
	RefreshToken string `+"`json:\"refresh_token\"`"+`
	ExpiresIn    int    `+"`json:\"expires_in\"`"+`
}

type LoginRequest struct {
	Email    string
	Password string
}

func list(w http.ResponseWriter, r *http.Request) {
	users := []model.User{{ID: 1, Email: "a@b.c", PasswordHash: "x"}}
	json.NewEncoder(w).Encode(users) // want "api-excessive-data-exposure:User.PasswordHash"
}

func nested(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)
	enc.Encode(map[string]*model.Account{}) // want "api-excessive-data-exposure:User.PasswordHash"
}

func marshaled(w http.ResponseWriter, r *http.Request) {
	b, _ := json.Marshal(model.Profile{})
	w.Write(b) // want "api-excessive-data-exposure:Profile.Salt"
}

func wrapped(w http.ResponseWriter, r *http.Request) {
	var u model.User
	json.NewEncoder(w).Encode(map[string]any{"user": u, "ok": true}) // want "api-excessive-data-exposure:User.PasswordHash"
}

func safe(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)
	enc.Encode([]model.SafeUser{})
	enc.Encode(UserResponseDTO{ID: 1, Email: "a@b.c"})
	enc.Encode(TokenResponse{AccessToken: "t", ExpiresIn: 3600})
	enc.Encode(LoginRequest{})
	enc.Encode(model.Custom{})
}

func toFile(enc *json.Encoder, u model.User) error {
	return enc.Encode(u)
}

func toBytes(u model.User) ([]byte, error) {
	return json.Marshal(u)
}
`), RegisterBOPLARules)
	for _, is := range issues {
		if strings.Contains(is.Description, "Profile.Salt") && !strings.Contains(is.Description, "'model.Profile'") {
			t.Errorf("description does not name the type: %s", is.Description)
		}
	}
}

func TestAPIBOPLAMassAssignment(t *testing.T) {
	t.Parallel()
	testutil.RunRulesOnFiles(t, boplaFiles(`package app

import (
	"encoding/json"
	"io"
	"net/http"

	"example.com/fixture/model"
)

type store interface {
	Save(v any) error
}

type plain struct {
	Name    string
	IsAdmin bool
}

type UpdateProfileRequest struct {
	Name string
}

func update(db store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var u model.User
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil { // want "api-mass-assignment:IsAdmin"
			return
		}
		db.Save(&u)
	}
}

func unmarshal(db store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		acct := &model.Account{}
		_ = json.Unmarshal(body, acct) // want "api-mass-assignment:Balance"
		_ = db.Save(acct)
	}
}

func unmarshalNotSaved(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	acct := &model.Account{}
	_ = json.Unmarshal(body, acct)
	_ = audit(acct)
}

func audit(a *model.Account) error { return nil }

func persistedPlain(db store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p plain
		_ = json.NewDecoder(r.Body).Decode(&p) // want "api-mass-assignment:IsAdmin"
		_ = db.Save(&p)
	}
}

func dto(db store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req UpdateProfileRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return
		}
		u := model.User{Email: req.Name}
		db.Save(&u)
	}
}

func readOnly(w http.ResponseWriter, r *http.Request) {
	var u model.SafeUser
	_ = json.NewDecoder(r.Body).Decode(&u)
}

func notPersisted(w http.ResponseWriter, r *http.Request) {
	var p plain
	_ = json.NewDecoder(r.Body).Decode(&p)
}

func fromFile(f io.Reader) (model.User, error) {
	var u model.User
	err := json.NewDecoder(f).Decode(&u)
	return u, err
}
`), RegisterBOPLARules)
}

func TestAPIBOPLAGin(t *testing.T) {
	t.Parallel()
	files := boplaFiles(`package app

import (
	"github.com/gin-gonic/gin"

	"example.com/fixture/model"
)

type ProfileInput struct {
	Name string
}

func show(c *gin.Context) {
	var u model.User
	c.JSON(200, u)                       // want "api-excessive-data-exposure:User.PasswordHash"
	c.JSON(200, gin.H{"users": []model.User{}}) // want "api-excessive-data-exposure"
	c.JSON(200, gin.H{"name": "ok"})
}

func edit(c *gin.Context) {
	var u model.User
	if err := c.ShouldBindJSON(&u); err != nil { // want "api-mass-assignment:IsAdmin"
		return
	}
	var in ProfileInput
	_ = c.ShouldBindJSON(&in)
}
`)
	files["go.mod"] = "module example.com/fixture\n\ngo 1.24\n\nrequire github.com/gin-gonic/gin v1.0.0\n\nreplace github.com/gin-gonic/gin => ./stubs/gin\n"
	files["stubs/gin/go.mod"] = "module github.com/gin-gonic/gin\n\ngo 1.24\n"
	files["stubs/gin/gin.go"] = `package gin

type H map[string]any

type Context struct{}

func (c *Context) JSON(code int, obj any)        {}
func (c *Context) ShouldBindJSON(obj any) error { return nil }
`
	testutil.RunRulesOnFiles(t, files, RegisterBOPLARules)
}
