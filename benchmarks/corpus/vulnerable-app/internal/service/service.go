// Package service implements the business operations.
package service

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/vulnerable-app/internal/model"
	"example.com/vulnerable-app/internal/repo"
)

// Service implements the operations of the API.
type Service struct {
	repo   *repo.Repo
	db     *sql.DB
	client *http.Client
}

// New returns a service.
func New(r *repo.Repo, db *sql.DB) *Service {
	return &Service{repo: r, db: db, client: &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}}
}

// SearchUsers returns the users matching filter.
func (s *Service) SearchUsers(ctx context.Context, filter string) ([]model.User, error) {
	return s.repo.FindByFilter(ctx, filter)
}

// CurrentUser returns the signed-in user.
func (s *Service) CurrentUser(ctx context.Context, id int64) (model.User, error) {
	return s.repo.UserByID(ctx, id)
}

// SaveAccount stores an account.
func (s *Service) SaveAccount(ctx context.Context, a *model.Account) error {
	return s.repo.Save(ctx, a)
}

// PingWebhook checks that a webhook URL answers.
func (s *Service) PingWebhook(ctx context.Context, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("webhook answered %s", resp.Status)
	}
	return nil
}

// PayOrder marks an order paid and charges the card.
func (s *Service) PayOrder(ctx context.Context, orderID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE orders SET status = 'paid' WHERE id = $1", orderID); err != nil {
		return err
	}
	if err := s.ChargeCard(ctx, orderID); err != nil {
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

// ExportReports concatenates report files into w.
func (s *Service) ExportReports(w io.Writer, paths []string) error {
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := io.Copy(w, f); err != nil {
			return err
		}
	}
	return nil
}

// ExtractArchive unpacks an uploaded archive into dest.
func (s *Service) ExtractArchive(archivePath, dest string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if err := extractFile(f, dest); err != nil {
			return err
		}
	}
	return nil
}

func extractFile(f *zip.File, dest string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(filepath.Join(dest, f.Name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, io.LimitReader(rc, 64<<20))
	return err
}
