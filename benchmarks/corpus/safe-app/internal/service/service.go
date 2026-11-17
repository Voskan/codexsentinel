// Package service implements the business operations.
package service

import (
	"archive/zip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/safe-app/internal/model"
	"example.com/safe-app/internal/repo"
)

// Service implements the operations of the API.
type Service struct {
	repo   *repo.Repo
	db     *sql.DB
	client *http.Client
}

// webhooks lists the webhook URLs that may be checked, by name.
var webhooks = map[string]string{
	"billing":  "https://billing.example.com/hook",
	"shipping": "https://shipping.example.com/hook",
}

// New returns a service.
func New(r *repo.Repo, db *sql.DB) *Service {
	return &Service{repo: r, db: db, client: &http.Client{Timeout: 10 * time.Second}}
}

// SearchUsers returns the users with a status.
func (s *Service) SearchUsers(ctx context.Context, status, sortBy string) ([]model.User, error) {
	return s.repo.FindByStatus(ctx, status, sortBy)
}

// CurrentUser returns the signed-in user.
func (s *Service) CurrentUser(ctx context.Context, id int64) (model.User, error) {
	return s.repo.UserByID(ctx, id)
}

// UpdateProfile applies the fields a user may change.
func (s *Service) UpdateProfile(ctx context.Context, id int64, req model.UpdateProfileRequest) error {
	return s.repo.UpdateName(ctx, id, req.Name)
}

// PingWebhook checks that a configured webhook answers.
func (s *Service) PingWebhook(ctx context.Context, name string) error {
	url, ok := webhooks[name]
	if !ok {
		return errors.New("unknown webhook")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("webhook answered %s", resp.Status)
	}
	return nil
}

// PayOrder charges the card first, then marks the order paid.
func (s *Service) PayOrder(ctx context.Context, orderID string) error {
	if err := s.ChargeCard(ctx, orderID); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "UPDATE orders SET status = 'paid' WHERE id = $1", orderID); err != nil {
		return err
	}
	return tx.Commit()
}

// ChargeCard asks the payment provider to charge an order.
func (s *Service) ChargeCard(ctx context.Context, orderID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://payments.example.com/charge", strings.NewReader(orderID))
	if err != nil {
		return err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("charge failed: %s", resp.Status)
	}
	return nil
}

// ExportReports concatenates report files into w, closing each file before
// opening the next.
func (s *Service) ExportReports(w io.Writer, paths []string) error {
	for _, p := range paths {
		if err := copyFile(w, p); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(w io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

// ExtractArchive unpacks an uploaded archive into dest; entries cannot leave
// dest because they are created through an os.Root.
func (s *Service) ExtractArchive(archivePath, dest string) error {
	root, err := os.OpenRoot(dest)
	if err != nil {
		return err
	}
	defer root.Close()
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if err := extractFile(root, f); err != nil {
			return err
		}
	}
	return nil
}

func extractFile(root *os.Root, f *zip.File) error {
	if err := root.MkdirAll(filepath.Dir(f.Name), 0o750); err != nil {
		return err
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := root.OpenFile(f.Name, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, io.LimitReader(rc, 64<<20))
	return err
}
