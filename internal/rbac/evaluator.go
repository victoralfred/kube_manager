package rbac

import (
	"context"
	"fmt"
	"reflect"
	"strings"
)

// ConditionEvaluator evaluates ABAC conditions
type ConditionEvaluator struct{}

// NewConditionEvaluator creates a new condition evaluator
func NewConditionEvaluator() *ConditionEvaluator {
	return &ConditionEvaluator{}
}

// EvaluationContext contains context for condition evaluation
type EvaluationContext struct {
	UserID    string
	TenantID  string
	Object    map[string]interface{} // The object being accessed
	User      map[string]interface{} // User attributes
	Tenant    map[string]interface{} // Tenant attributes
	Variables map[string]interface{} // Additional variables
}

// Evaluate evaluates a condition against the evaluation context
func (e *ConditionEvaluator) Evaluate(ctx context.Context, condition *Condition, evalCtx *EvaluationContext) (bool, error) {
	if condition == nil {
		return true, nil // No condition means allowed
	}

	if len(condition.Rules) == 0 {
		return true, nil
	}

	switch strings.ToUpper(condition.Operator) {
	case "AND":
		return e.evaluateAND(ctx, condition.Rules, evalCtx)
	case "OR":
		return e.evaluateOR(ctx, condition.Rules, evalCtx)
	default:
		return false, fmt.Errorf("unknown condition operator: %s", condition.Operator)
	}
}

// evaluateAND returns true only if ALL rules evaluate to true
func (e *ConditionEvaluator) evaluateAND(ctx context.Context, rules []Rule, evalCtx *EvaluationContext) (bool, error) {
	for _, rule := range rules {
		result, err := e.evaluateRule(ctx, rule, evalCtx)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil // Short circuit on first false
		}
	}
	return true, nil
}

// evaluateOR returns true if ANY rule evaluates to true
func (e *ConditionEvaluator) evaluateOR(ctx context.Context, rules []Rule, evalCtx *EvaluationContext) (bool, error) {
	for _, rule := range rules {
		result, err := e.evaluateRule(ctx, rule, evalCtx)
		if err != nil {
			return false, err
		}
		if result {
			return true, nil // Short circuit on first true
		}
	}
	return false, nil
}

// evaluateRule evaluates a single rule
func (e *ConditionEvaluator) evaluateRule(ctx context.Context, rule Rule, evalCtx *EvaluationContext) (bool, error) {
	// Resolve the field value from the object
	fieldValue, err := e.resolveField(rule.Field, evalCtx)
	if err != nil {
		return false, err
	}

	// Resolve the expected value (may contain variables like ${user.id})
	expectedValue, err := e.resolveValue(rule.Value, evalCtx)
	if err != nil {
		return false, err
	}

	// Apply operator
	switch strings.ToLower(rule.Operator) {
	case "equals", "eq":
		return e.equals(fieldValue, expectedValue), nil
	case "not_equals", "ne", "neq":
		return !e.equals(fieldValue, expectedValue), nil
	case "in":
		return e.in(fieldValue, expectedValue), nil
	case "not_in":
		return !e.in(fieldValue, expectedValue), nil
	case "contains":
		return e.contains(fieldValue, expectedValue), nil
	case "starts_with":
		return e.startsWith(fieldValue, expectedValue), nil
	case "ends_with":
		return e.endsWith(fieldValue, expectedValue), nil
	case "greater_than", "gt":
		return e.greaterThan(fieldValue, expectedValue), nil
	case "less_than", "lt":
		return e.lessThan(fieldValue, expectedValue), nil
	case "exists":
		return fieldValue != nil, nil
	case "not_exists":
		return fieldValue == nil, nil
	default:
		return false, fmt.Errorf("unknown operator: %s", rule.Operator)
	}
}

// resolveField resolves a field path from the evaluation context
// Examples: "owner_id", "created_by", "status", "user.id", "tenant.plan"
func (e *ConditionEvaluator) resolveField(field string, evalCtx *EvaluationContext) (interface{}, error) {
	parts := strings.Split(field, ".")

	// Root object
	var root map[string]interface{}
	switch parts[0] {
	case "user":
		root = evalCtx.User
	case "tenant":
		root = evalCtx.Tenant
	case "object":
		root = evalCtx.Object
	default:
		// Assume it's a field on the object
		root = evalCtx.Object
		parts = []string{parts[0]} // Reset parts for direct field access
	}

	if root == nil {
		return nil, nil
	}

	// Navigate nested fields
	current := root
	for i, part := range parts {
		if i == 0 && (part == "user" || part == "tenant" || part == "object") {
			continue // Skip the root identifier
		}

		value, ok := current[part]
		if !ok {
			return nil, nil
		}

		// If this is the last part, return the value
		if i == len(parts)-1 {
			return value, nil
		}

		// Otherwise, it should be another map
		nextMap, ok := value.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("field path %s is not navigable", field)
		}
		current = nextMap
	}

	return nil, nil
}

// resolveValue resolves variable references in values
// Examples: "${user.id}", "${tenant.id}", "draft", ["active", "pending"]
func (e *ConditionEvaluator) resolveValue(value interface{}, evalCtx *EvaluationContext) (interface{}, error) {
	// If it's a string, check for variable references
	if strValue, ok := value.(string); ok {
		if strings.HasPrefix(strValue, "${") && strings.HasSuffix(strValue, "}") {
			// Extract variable name
			varName := strings.TrimSuffix(strings.TrimPrefix(strValue, "${"), "}")

			// Resolve variable
			switch varName {
			case "user.id":
				return evalCtx.UserID, nil
			case "tenant.id":
				return evalCtx.TenantID, nil
			default:
				// Try to resolve from context
				return e.resolveField(varName, evalCtx)
			}
		}
	}

	return value, nil
}

// equals checks if two values are equal
func (e *ConditionEvaluator) equals(a, b interface{}) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}

	return reflect.DeepEqual(a, b)
}

// in checks if a value is in a list
func (e *ConditionEvaluator) in(value, list interface{}) bool {
	if list == nil {
		return false
	}

	// Convert list to slice
	listValue := reflect.ValueOf(list)
	if listValue.Kind() != reflect.Slice && listValue.Kind() != reflect.Array {
		return false
	}

	for i := 0; i < listValue.Len(); i++ {
		if e.equals(value, listValue.Index(i).Interface()) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring
func (e *ConditionEvaluator) contains(value, substring interface{}) bool {
	strValue, ok1 := value.(string)
	strSubstring, ok2 := substring.(string)
	if !ok1 || !ok2 {
		return false
	}

	return strings.Contains(strValue, strSubstring)
}

// startsWith checks if a string starts with a prefix
func (e *ConditionEvaluator) startsWith(value, prefix interface{}) bool {
	strValue, ok1 := value.(string)
	strPrefix, ok2 := prefix.(string)
	if !ok1 || !ok2 {
		return false
	}

	return strings.HasPrefix(strValue, strPrefix)
}

// endsWith checks if a string ends with a suffix
func (e *ConditionEvaluator) endsWith(value, suffix interface{}) bool {
	strValue, ok1 := value.(string)
	strSuffix, ok2 := suffix.(string)
	if !ok1 || !ok2 {
		return false
	}

	return strings.HasSuffix(strValue, strSuffix)
}

// greaterThan compares two values
func (e *ConditionEvaluator) greaterThan(a, b interface{}) bool {
	// Convert to float64 for comparison
	aFloat, aOk := e.toFloat64(a)
	bFloat, bOk := e.toFloat64(b)

	if !aOk || !bOk {
		return false
	}

	return aFloat > bFloat
}

// lessThan compares two values
func (e *ConditionEvaluator) lessThan(a, b interface{}) bool {
	aFloat, aOk := e.toFloat64(a)
	bFloat, bOk := e.toFloat64(b)

	if !aOk || !bOk {
		return false
	}

	return aFloat < bFloat
}

// toFloat64 converts various numeric types to float64
func (e *ConditionEvaluator) toFloat64(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	default:
		return 0, false
	}
}

// CheckOwnership is a simplified ownership check (part of ABAC)
func CheckOwnership(userID, resourceOwnerID string) bool {
	return userID == resourceOwnerID
}
