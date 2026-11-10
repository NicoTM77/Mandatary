package authz

import (
	"database/sql"

	"github.com/NicoTM77/Mandatary/internal/docker"
)

// Approved Phase 1 permission keys (TD §§2.1, 3.3).
const (
	OpContainerLogs          docker.Operation = docker.OpLogs
	OpContainerInspectStatus docker.Operation = docker.OpInspectStatus
	OpContainerInspectConfig docker.Operation = docker.OpInspectConfig
	OpContainerStart         docker.Operation = docker.OpStart
	OpContainerStop          docker.Operation = docker.OpStop
	OpContainerRestart       docker.Operation = docker.OpRestart
)

// AllOperations returns the exact six approved Phase 1 permission keys in canonical order.
func AllOperations() []docker.Operation {
	return []docker.Operation{
		OpContainerLogs,
		OpContainerInspectStatus,
		OpContainerInspectConfig,
		OpContainerStart,
		OpContainerStop,
		OpContainerRestart,
	}
}

// ValidateRequestParameters validates operation membership and operation-specific parameter options,
// reusing the existing docker.ValidateLogOptions and docker.ValidateStopTimeout bounds (TD §§1.2, 3.3, 10.2).
func ValidateRequestParameters(
	op docker.Operation,
	logOpts *docker.LogOptions,
	stopOpts *docker.StopOptions,
	restartOpts *docker.RestartOptions,
) (*docker.LogOptions, *int, error) {
	if err := docker.ValidateOperation(op); err != nil {
		return nil, nil, newForbidden(ReasonInvalidOperation)
	}

	switch op {
	case OpContainerLogs:
		if stopOpts != nil || restartOpts != nil {
			return nil, nil, newForbidden(ReasonInvalidParameters)
		}
		raw := docker.LogOptions{
			Tail:   docker.DefaultLogTail,
			Stdout: true,
			Stderr: true,
		}
		if logOpts != nil {
			raw = *logOpts
		}
		validated, err := docker.ValidateLogOptions(raw)
		if err != nil {
			return nil, nil, newForbidden(ReasonInvalidParameters)
		}
		return &validated, nil, nil

	case OpContainerStop:
		if logOpts != nil || restartOpts != nil {
			return nil, nil, newForbidden(ReasonInvalidParameters)
		}
		var timeoutPtr *int
		if stopOpts != nil {
			timeoutPtr = stopOpts.TimeoutSeconds
		}
		timeoutSec, err := docker.ValidateStopTimeout(timeoutPtr)
		if err != nil {
			return nil, nil, newForbidden(ReasonInvalidParameters)
		}
		return nil, &timeoutSec, nil

	case OpContainerRestart:
		if logOpts != nil || stopOpts != nil {
			return nil, nil, newForbidden(ReasonInvalidParameters)
		}
		var timeoutPtr *int
		if restartOpts != nil {
			timeoutPtr = restartOpts.TimeoutSeconds
		}
		timeoutSec, err := docker.ValidateStopTimeout(timeoutPtr)
		if err != nil {
			return nil, nil, newForbidden(ReasonInvalidParameters)
		}
		return nil, &timeoutSec, nil

	case OpContainerInspectStatus, OpContainerInspectConfig, OpContainerStart:
		if logOpts != nil || stopOpts != nil || restartOpts != nil {
			return nil, nil, newForbidden(ReasonInvalidParameters)
		}
		return nil, nil, nil

	default:
		return nil, nil, newForbidden(ReasonInvalidOperation)
	}
}

// SatisfiesPolicyConstraints checks whether normalized request parameters satisfy an ALLOW policy's caps.
func SatisfiesPolicyConstraints(
	op docker.Operation,
	normLog *docker.LogOptions,
	normTimeout *int,
	logTailMax sql.NullInt64,
	stopTimeoutMax sql.NullInt64,
) bool {
	switch op {
	case OpContainerLogs:
		if stopTimeoutMax.Valid {
			return false
		}
		if logTailMax.Valid {
			if logTailMax.Int64 < docker.MinLogTail || logTailMax.Int64 > docker.MaxLogTail {
				return false
			}
			if normLog == nil || int64(normLog.Tail) > logTailMax.Int64 {
				return false
			}
		}
		return true

	case OpContainerStop, OpContainerRestart:
		if logTailMax.Valid {
			return false
		}
		if stopTimeoutMax.Valid {
			if stopTimeoutMax.Int64 < docker.MinStopTimeoutSeconds || stopTimeoutMax.Int64 > docker.MaxStopTimeoutSeconds {
				return false
			}
			if normTimeout == nil || int64(*normTimeout) > stopTimeoutMax.Int64 {
				return false
			}
		}
		return true

	case OpContainerInspectStatus, OpContainerInspectConfig, OpContainerStart:
		return !logTailMax.Valid && !stopTimeoutMax.Valid

	default:
		return false
	}
}
