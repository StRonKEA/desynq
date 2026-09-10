//go:build windows

package windns

import (
	"context"

	"dpi/internal/apply"
	"golang.org/x/sys/windows/svc"
)

type Service struct {
	toolsDir string
	dohURL   string
}

func NewService(toolsDir, dohURL string) *Service {
	return &Service{toolsDir: toolsDir, dohURL: dohURL}
}

func (s *Service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}

	d, err := New(s.toolsDir, s.dohURL)
	if err != nil {
		return true, 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := d.Start(ctx); err != nil {
		return true, 2
	}
	defer d.Stop()

	_ = apply.FlushDNSCache()
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			_ = apply.FlushDNSCache()
			return false, 0
		}
	}
	return false, 0
}

// RunService starts the transparent DoH diverter under Windows Service Control Manager.
func RunService(toolsDir, dohURL string) error {
	return svc.Run("desynq-dns", NewService(toolsDir, dohURL))
}
