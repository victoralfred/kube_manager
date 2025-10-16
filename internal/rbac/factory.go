package rbac

import (
	"time"

	"github.com/victoralfred/kube_manager/pkg/cache"
	"github.com/victoralfred/kube_manager/pkg/database"
	"github.com/victoralfred/kube_manager/pkg/logger"
)

// Module holds all RBAC module components
type Module struct {
	Repository   Repository
	PolicyEngine PolicyEngine
	Registry     *ResourceRegistry
	Service      Service
	Handler      *Handler
}

// ModuleConfig holds configuration for RBAC module
type ModuleConfig struct {
	Cache    cache.Cache
	CacheTTL time.Duration
}

// NewModule creates and initializes the RBAC module using factory pattern
func NewModule(db *database.DB, cfg ModuleConfig, log *logger.Logger) *Module {
	// Create repository
	repo := NewRepository(db)

	// Create resource registry
	registry := NewResourceRegistry()

	// Create policy engine with cache
	policyEngine := NewPolicyEngine(PolicyEngineConfig{
		Repository: repo,
		Cache:      cfg.Cache,
		CacheTTL:   cfg.CacheTTL,
	})

	// Create service with all dependencies
	svc := NewService(repo, policyEngine, registry, log)

	// Create handler with service dependency
	handler := NewHandler(svc)

	return &Module{
		Repository:   repo,
		PolicyEngine: policyEngine,
		Registry:     registry,
		Service:      svc,
		Handler:      handler,
	}
}

// GetService returns the RBAC service
func (m *Module) GetService() Service {
	return m.Service
}

// GetHandler returns the RBAC handler
func (m *Module) GetHandler() *Handler {
	return m.Handler
}

// GetRepository returns the RBAC repository
func (m *Module) GetRepository() Repository {
	return m.Repository
}

// GetPolicyEngine returns the policy engine
func (m *Module) GetPolicyEngine() PolicyEngine {
	return m.PolicyEngine
}

// GetRegistry returns the resource registry
func (m *Module) GetRegistry() *ResourceRegistry {
	return m.Registry
}
