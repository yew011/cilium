// Copyright 2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package observer2

import (
	"context"
	"errors"
	"strings"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/hubble/container2"
	"github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/cilium/pkg/hubble/metrics"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser"
	parserErrors "github.com/cilium/cilium/pkg/hubble/parser/errors"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	"github.com/golang/protobuf/ptypes"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A LocalObserverServer is an implementation of the server.Observer interface
// that's meant to be run embedded inside the Cilium process. It ignores all the
// state change events since the state is available locally.
type LocalObserverServer struct {
	logger         logrus.FieldLogger
	maxFlows       int
	eventQueueSize int
	payloadParser  *parser.Parser
	nodeName       string
	ringBuffer     *container2.RingBuffer
	events         chan *observerTypes.MonitorEvent
	startTime      time.Time
}

// A LocalObserverServerOption sets an option on a LocalObserverServer.
type LocalObserverServerOption func(*LocalObserverServer)

// WithEventQueueSize sets the event queue size.
func WithEventQueueSize(eventQueueSize int) LocalObserverServerOption {
	return func(s *LocalObserverServer) {
		s.eventQueueSize = eventQueueSize
	}
}

// WithLogger sets the logger.
func WithLogger(logger logrus.FieldLogger) LocalObserverServerOption {
	return func(s *LocalObserverServer) {
		s.logger = logger
	}
}

// WithMaxFlows sets the max flows.
func WithMaxFlows(maxFlows int) LocalObserverServerOption {
	return func(s *LocalObserverServer) {
		s.maxFlows = maxFlows
	}
}

// WithPayloadParser sets the payload parser.
func WithPayloadParser(payloadParser *parser.Parser) LocalObserverServerOption {
	return func(s *LocalObserverServer) {
		s.payloadParser = payloadParser
	}
}

// NewLocalObserverServer returns a new LocalObserverServer with the given
// options.
func NewLocalObserverServer(options ...LocalObserverServerOption) *LocalObserverServer {
	s := &LocalObserverServer{
		maxFlows:       4096,
		eventQueueSize: 1024,
		nodeName:       nodeTypes.GetName(),
	}
	for _, o := range options {
		o(s)
	}

	s.logger.WithFields(logrus.Fields{
		"maxFlows":       s.maxFlows,
		"eventQueueSize": s.eventQueueSize,
	}).Info("Configuring Hubble server")

	s.ringBuffer = container2.NewRingBuffer(
		container2.WithCapacity(s.maxFlows),
	)
	s.events = make(chan *observerTypes.MonitorEvent, s.eventQueueSize)
	return s
}

// GetEventsChannel returns s's events channel.
func (s *LocalObserverServer) GetEventsChannel() chan *observerTypes.MonitorEvent {
	return s.events
}

// GetFlows FIXME.
func (s *LocalObserverServer) GetFlows(req *observerpb.GetFlowsRequest, server observerpb.Observer_GetFlowsServer) error {
	ctx, cancel := context.WithCancel(server.Context())
	defer cancel()

	filterList := filters.DefaultFilters
	includeList, err := filters.BuildFilterList(ctx, req.Whitelist, filterList)
	if err != nil {
		return err
	}
	excludeList, err := filters.BuildFilterList(ctx, req.Blacklist, filterList)
	if err != nil {
		return err
	}

	s.logger.WithFields(logrus.Fields{
		"req":          req,
		"include_list": includeList,
		"exclude_list": excludeList,
	}).Debug("GetFlows starting")

	flowsSent := uint64(0)
	startTime := time.Now()
	defer func() {
		s.logger.WithFields(logrus.Fields{
			"number_of_flows": flowsSent,
			"buffer_size":     s.maxFlows,
			"include_list":    logFilters(req.Whitelist),
			"exclude_list":    logFilters(req.Blacklist),
			"took":            time.Since(startTime),
		}).Debug("GetFlows finished")
	}()

	var since time.Time
	if req.Since != nil {
		since, err = ptypes.Timestamp(req.Since)
		if err != nil {
			return err
		}
	}

	var until time.Time
	if req.Until != nil {
		until, err = ptypes.Timestamp(req.Until)
		if err != nil {
			return err
		}
	}

	var ch <-chan *v1.Event
	var cancelRead container2.ReaderCancelFunc
	if !since.IsZero() {
		ch, cancelRead = s.ringBuffer.ReadSince(since, 0)
	} else if req.Follow {
		ch, cancelRead = s.ringBuffer.ReadAll(0)
	} else {
		ch, cancelRead = s.ringBuffer.ReadCurrent(0)
	}
	defer cancelRead()

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-ch:
			if !ok {
				return nil
			}

			if !until.IsZero() {
				ts, err := ptypes.Timestamp(event.GetFlow().GetTime())
				if err != nil {
					return err
				}
				if !ts.Before(until) {
					return nil
				}
			}

			switch e := event.Event.(type) {
			case *flowpb.Flow:
				if filters.Apply(includeList, excludeList, event) {
					if err := server.Send(&observerpb.GetFlowsResponse{
						Time:     e.GetTime(),
						NodeName: e.GetNodeName(),
						ResponseTypes: &observerpb.GetFlowsResponse_Flow{
							Flow: e,
						},
					}); err != nil {
						return err
					}
					flowsSent++
					if req.Number != 0 && flowsSent >= req.Number {
						return nil
					}
				}
			case *flowpb.LostEvent:
				if err := server.Send(&observerpb.GetFlowsResponse{
					Time:     event.Timestamp,
					NodeName: s.nodeName,
					ResponseTypes: &observerpb.GetFlowsResponse_LostEvents{
						LostEvents: e,
					},
				}); err != nil {
					return err
				}
			case *flowpb.AgentEvent:
				if err := server.Send(&observerpb.GetFlowsResponse{
					Time:     event.Timestamp,
					NodeName: s.nodeName,
					ResponseTypes: &observerpb.GetFlowsResponse_AgentEvent{
						AgentEvent: e,
					},
				}); err != nil {
					return err
				}
			}
		}
	}
}

// GetLogger returns s's logger.
func (s *LocalObserverServer) GetLogger() logrus.FieldLogger {
	return s.logger
}

// GetNodes implements observerpb.ObserverClient.GetNodes.
func (s *LocalObserverServer) GetNodes(ctx context.Context, req *observerpb.GetNodesRequest) (*observerpb.GetNodesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "GetNodes not implemented")
}

// ServerStatus returns s's status.
func (s *LocalObserverServer) ServerStatus(ctx context.Context, req *observerpb.ServerStatusRequest) (*observerpb.ServerStatusResponse, error) {
	status := s.ringBuffer.Status()
	return &observerpb.ServerStatusResponse{
		MaxFlows:  uint64(s.maxFlows),
		NumFlows:  uint64(status.NumEvents),
		SeenFlows: uint64(status.SeenEvents),
		UptimeNs:  uint64(time.Since(s.startTime).Nanoseconds()),
	}, nil
}

// Start implements GRPCServer.Start.
func (s *LocalObserverServer) Start() {
	s.startTime = time.Now()

	for monitorEvent := range s.events {
		event, err := s.payloadParser.Decode(monitorEvent)
		if err != nil {
			if !errors.Is(err, parserErrors.ErrUnknownEventType) {
				s.logger.WithError(err).WithField("event", monitorEvent).Debug("failed to decode payload")
			}
			continue
		}

		if flow, ok := event.Event.(*flowpb.Flow); ok {
			metrics.ProcessFlow(flow)
		}

		s.ringBuffer.Write(event)
	}
}

func logFilters(filters []*flowpb.FlowFilter) string {
	s := make([]string, 0, len(filters))
	for _, f := range filters {
		s = append(s, f.String())
	}
	return "{" + strings.Join(s, ",") + "}"
}
