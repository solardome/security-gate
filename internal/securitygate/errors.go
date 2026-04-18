package securitygate

import "errors"

var (
	ErrPolicyLoad        = errors.New("policy load failed")
	ErrContextLoad       = errors.New("context load failed")
	ErrAcceptedRiskLoad  = errors.New("accepted risk load failed")
	ErrScanUnreadable    = errors.New("scan file unreadable")
	ErrScanParseFailed   = errors.New("scan parse failed")
	ErrUnsupportedFormat = errors.New("unsupported scan format")
)
