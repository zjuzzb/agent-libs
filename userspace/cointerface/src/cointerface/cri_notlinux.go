//go:build !linux
// +build !linux

package main

import (
	"errors"
)

var errNotImplemented = errors.New("CriClient not implemented on your platform")

// CriClient is currently not implemented for platforms different than linux.
type CriClient struct {
}

// NewCriClient creates a new CriClient instance.
func NewCriClient(_ string) (*CriClient, error) {
	return nil, errNotImplemented
}

func (c *CriClient) Close() error {
	return errNotImplemented
}

func (c *CriClient) StopContainer(_ string, _ int64) error {
	return errNotImplemented
}

func (c *CriClient) PauseContainer(_ string) error {
	return errNotImplemented
}

func (c *CriClient) UnpauseContainer(_ string) error {
	return errNotImplemented
}
