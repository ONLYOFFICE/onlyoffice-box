package controller

import (
	"errors"

	"golang.org/x/sync/singleflight"
)

var (
	group singleflight.Group
)

var (
	ErrSemaphoreNotAllowed = errors.New("could not acquire semaphore")
)
