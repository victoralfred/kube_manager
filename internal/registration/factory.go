package registration

import (
	"github.com/victoralfred/kube_manager/internal/auth"
	"github.com/victoralfred/kube_manager/internal/rbac"
	"github.com/victoralfred/kube_manager/internal/tenant"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// Module holds all registration components
type Module struct {
	Service Service
}

// NewModule creates a new registration module with all dependencies
func NewModule(
	authRepo auth.Repository,
	verificationRepo auth.VerificationRepository,
	tenantService tenant.Service,
	rbacService rbac.Service,
	jwtService *auth.JWTService,
	log *logger.Logger,
) *Module {
	// Create service
	svc := NewService(authRepo, verificationRepo, tenantService, rbacService, jwtService, log)

	return &Module{
		Service: svc,
	}
}
