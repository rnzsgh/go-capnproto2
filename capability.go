package capnp

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"

	"golang.org/x/net/context"
)

// An Interface is a reference to a client in a message's capability table.
type Interface struct {
	seg *Segment
	cap CapabilityID
}

// NewInterface creates a new interface pointer.  No allocation is
// performed; s is only used for Segment()'s return value.
func NewInterface(s *Segment, cap CapabilityID) Interface {
	return Interface{
		seg: s,
		cap: cap,
	}
}

// ToPtr converts the interface to a generic pointer.
func (p Interface) ToPtr() Ptr {
	return Ptr{
		seg:      p.seg,
		lenOrCap: uint32(p.cap),
		flags:    interfacePtrFlag,
	}
}

// Segment returns the segment this pointer came from.
func (i Interface) Segment() *Segment {
	return i.seg
}

// IsValid returns whether the interface is valid.
func (i Interface) IsValid() bool {
	return i.seg != nil
}

// Capability returns the capability ID of the interface.
func (i Interface) Capability() CapabilityID {
	return i.cap
}

// value returns a raw interface pointer with the capability ID.
func (i Interface) value(paddr Address) rawPointer {
	if i.seg == nil {
		return 0
	}
	return rawInterfacePointer(i.cap)
}

// Client returns a new reference to the client stored in the message's
// capability table or nil if the pointer is invalid.  The caller is
// responsible for closing the returned client.
func (i Interface) Client() *Client {
	if i.seg == nil {
		return nil
	}
	tab := i.seg.msg.CapTable
	if int64(i.cap) >= int64(len(tab)) {
		return nil
	}
	return tab[i.cap].AddRef()
}

// ErrNullClient is returned from a call made on a null client pointer.
var ErrNullClient = errors.New("capnp: call on null client")

// A CapabilityID is an index into a message's capability table.
type CapabilityID uint32

// A Client is a reference to a Cap'n Proto capability.
// The zero value is a null capability reference.
// It is safe to use from multiple goroutines.
type Client struct {
	mu      sync.Mutex  // protects the struct
	h       *clientHook // nil if resolved to nil or closed
	closed  bool
	closing *clientHook
}

// NewClient creates the first reference to a capability.
// If hook is nil, then NewClient returns nil.
//
// Typically the RPC system will create a client for the application.
// Most applications will not need to use this directly.
func NewClient(hook ClientHook) *Client {
	if hook == nil {
		return nil
	}
	return &Client{h: newClientHook(hook)}
}

// startCall holds onto a hook to prevent it from closing until finish is called.
// It resolves the client's hook as much as possible without blocking first.
// The caller must not be holding onto c.mu.
func (c *Client) startCall() (hook *clientHook, closed bool, finish func()) {
	defer c.mu.Unlock()
	c.mu.Lock()
	if c.h == nil {
		return nil, c.closed, func() {}
	}
	var dead []*clientHook
	finish = func() {
		c.mu.Lock()
		// hook is captured as c.h at startCall's return.
		hook.mu.Lock()
		hook.calls--
		if hook.refs == 0 && hook.calls == 0 {
			close(hook.done)
			if hook != c.closing {
				dead = append(dead, hook)
			}
		}
		hook.mu.Unlock()
		c.mu.Unlock()

		for _, h := range dead {
			<-h.done
			// TODO(maybe): Log error somewhere?
			h.Close()
		}
	}
	// Caller must be holding c.h.mu and if rh != nil, rh.mu.
	lockedResolve := func(rh *clientHook) {
		c.h.resolved = true
		c.h.resolvedHook = rh
		if c.h == rh {
			return
		}
		c.h.refs--
		if c.h.refs == 0 && c.h.calls == 0 {
			close(c.h.done)
			dead = append(dead, c.h)
		}
		c.h.mu.Unlock()
		c.h = rh
	}

	c.h.mu.Lock() // Must be unlocked before returning.
	for {
		if c.h.resolved {
			// Fast path: client has already been resolved.
			rh := c.h.resolvedHook
			if rh == c.h {
				c.h.calls++
				c.h.mu.Unlock()
				return c.h, c.closed, finish
			}
			if rh == nil {
				lockedResolve(nil)
				return nil, false, finish
			}
			rh.mu.Lock()
			// TODO(soon): upper bound on iterations
			for rh.resolved && rh.resolvedHook != rh {
				rr := rh.resolvedHook
				rh.mu.Unlock()
				if rr == nil {
					lockedResolve(nil)
					return nil, false, func() {}
				}
				if rr == c.h {
					panic("resolution cycle")
				}
				rh = rr
				rh.mu.Lock()
			}
			// After the above loop, the following things are true:
			// 1) c.h != nil
			// 2) We are holding c.h.mu
			// 3) rh != nil
			// 4) c.h != rh
			// 5) We are holding rh.mu
			// 6) rh.resolved == false

			if rh.refs == 0 {
				panic("resolved to closed client")
			}
			rh.refs++
			lockedResolve(rh)
		}
		c.h.calls++
		c.h.mu.Unlock()

		select {
		case <-c.h.Resolved():
		default:
			// Common case: not resolved yet.
			return c.h, false, finish
		}

		r := c.h.ResolvedClient()
		c.h.mu.Lock()
		if r == nil {
			c.h.calls--
			lockedResolve(nil)
			return nil, false, func() {}
		}
		if r == c {
			lockedResolve(c.h)
			c.h.mu.Unlock()
			return c.h, false, finish
		}

		// TODO(someday): This lock seems dicey.
		// As long as there is not a resolution cycle (i.e. the order of
		// c.mu.Lock and r.mu.Lock will not change), then this will not
		// deadlock.  However, I can't really prove to myself that it won't.
		r.mu.Lock()

		if r.closed {
			panic(fmt.Sprintf("%T.ResolvedClient returned a closed client", c.h))
		}
		if r.h == c.h {
			r.mu.Unlock()
			lockedResolve(c.h)
			c.h.mu.Unlock()
			return c.h, false, finish
		}
		c.h.calls--
		if r.h == nil {
			r.mu.Unlock()
			lockedResolve(nil)
			return nil, false, func() {}
		}
		// Past this point, things we know:
		// 1) r.h has at least one reference (r) until r.mu is unlocked.
		// 2) c.h != r.h
		r.h.mu.Lock()
		lockedResolve(r.h)
		r.mu.Unlock()
		c.h.refs++
	}
}

// Call starts executing a method and returns an answer that will hold
// the resulting struct.  The call's parameters must be placed before
// Call() returns.  Calls to an invalid client return an error.
//
// Calls are delivered to the capability in the order they are made.
// This guarantee is based on the concept of a capability
// acknowledging delivery of a call: this is specific to an
// implementation of Client.  A type that implements Client must
// guarantee that if foo() then bar() is called on a client, that
// acknowledging foo() happens before acknowledging bar().
func (c *Client) Call(ctx context.Context, call *Call) (_ *Pipeline, finish func()) {
	if c == nil {
		return ErrorAnswer(ErrNullClient)
	}
	h, closed, finish := c.startCall()
	defer finish()
	if closed {
		return ErrorAnswer(errors.New("capnp: call on closed client"))
	}
	if h == nil {
		return ErrorAnswer(ErrNullClient)
	}
	return h.Call(ctx, call)
}

// IsValid reports whether c is a valid reference to a capability.
// A reference is invalid if it is nil, has resolved to null, or has
// been closed.
func (c *Client) IsValid() bool {
	if c == nil {
		return false
	}
	h, closed, finish := c.startCall()
	finish()
	return !closed && h != nil
}

// IsSame reports whether c and c2 refer to a capability created by the
// same call to NewClient.  This can return false negatives if c or c2
// are not fully resolved: use Resolve if this is an issue.  If either
// c or c2 are closed, then IsSame panics.
func (c *Client) IsSame(c2 *Client) bool {
	var (
		h1     *clientHook
		closed bool
		finish func()
	)
	if c != nil {
		h1, closed, finish = c.startCall()
		finish()
		if closed {
			panic("IsSame on closed client")
		}
	}
	var h2 *clientHook
	if c2 != nil {
		h2, closed, finish = c2.startCall()
		finish()
		if closed {
			panic("IsSame on closed client")
		}
	}
	return h1 == h2
}

// Resolve blocks until the capability is fully resolved or the Context is Done.
func (c *Client) Resolve(ctx context.Context) error {
	if c == nil {
		return nil
	}
	for {
		h, closed, finish := c.startCall()
		if closed {
			finish()
			return errors.New("capnp: cannot resolve closed client")
		}
		if h == nil {
			finish()
			return nil
		}
		resolved := h.Resolved()
		finish()

		if resolved == nil {
			return nil
		}
		select {
		case <-resolved:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// AddRef creates a new Client that refers to the same capability as c.
// If c is nil or has resolved to null, then AddRef returns nil.
func (c *Client) AddRef() *Client {
	if c == nil {
		return nil
	}
	defer c.mu.Unlock()
	c.mu.Lock()
	if c.closed {
		panic("AddRef on closed client")
	}
	h := c.h
	if h == nil {
		return nil
	}
	h.mu.Lock()
	h.refs++
	h.mu.Unlock()
	return &Client{h: h}
}

// WeakRef creates a new WeakClient that refers to the same capability
// as c.  If c is nil or has resolved to null, then WeakRef returns nil.
func (c *Client) WeakRef() *WeakClient {
	if c == nil {
		return nil
	}
	defer c.mu.Unlock()
	c.mu.Lock()
	if c.closed {
		panic("WeakRef on closed client")
	}
	h := c.h
	if h == nil {
		return nil
	}
	return &WeakClient{h: h}
}

// Brand returns the current underlying hook's Brand method or nil if
// c is nil, has resolved to null, or has been closed.
func (c *Client) Brand() interface{} {
	if c == nil {
		return nil
	}
	h, _, finish := c.startCall()
	defer finish()
	if h == nil {
		return nil
	}
	return h.Brand()
}

// Close releases a capability reference.  If this is the last reference
// to the capability, then the underlying resources associated with the
// capability will be released.  Close returns an error if c has already
// been closed, but not if c is nil or resolved to null.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	// We don't use start() here because:
	// 1) We need to mutate c.h (set to nil)
	// 2) We don't want the extra locking around incrementing the call count
	// 3) We don't want the extra locking around resolving clients.
	//    It is always safe to close the hook we already have.
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("capnp: double close on Client")
	}
	c.closed = true
	h := c.h
	if h == nil {
		c.mu.Unlock()
		return nil
	}
	c.closing = h
	h.mu.Lock()
	h.refs--
	if h.refs > 0 {
		h.mu.Unlock()
		c.h = nil
		c.closing = nil
		c.mu.Unlock()
		return nil
	}
	// This was the last reference. Close the hook.
	if h.calls == 0 {
		close(h.done)
	}
	h.mu.Unlock()
	c.h = nil
	c.mu.Unlock()
	<-h.done
	err := h.Close()
	c.mu.Lock()
	c.closing = nil
	c.mu.Unlock()
	return err
}

// A WeakClient is a weak reference to a capability: it refers to a
// capability without preventing it from being closed.  The zero value
// is a null reference.
type WeakClient struct {
	h *clientHook
}

// AddRef creates a new Client that refers to the same capability as c
// as long as the capability hasn't already been closed.
func (wc *WeakClient) AddRef() (c *Client, ok bool) {
	if wc == nil {
		return nil, true
	}
	for {
		if wc.h == nil {
			return nil, true
		}
		wc.h.mu.Lock()
		if wc.h.resolved {
			if r := wc.h.resolvedHook; r != wc.h {
				wc.h.mu.Unlock()
				wc.h = r
				continue
			}
		}
		if wc.h.refs == 0 {
			wc.h.mu.Unlock()
			return nil, false
		}
		wc.h.refs++
		wc.h.mu.Unlock()
		return &Client{h: wc.h}, true
	}
}

// clientHook is a reference-counted wrapper for a ClientHook.
// It is assumed that a clientHook's address uniquely identifies a hook,
// since they are only created in NewClient.
type clientHook struct {
	// ClientHook will never be nil and will not change for the lifetime of a
	// clientHook.
	ClientHook

	// done is closed when refs == 0 and calls == 0.
	done chan struct{}

	mu           sync.Mutex // guards the following fields
	refs         int        // how many open Clients reference this clientHook
	calls        int        // number of outstanding ClientHook accesses
	resolved     bool
	resolvedHook *clientHook
}

func newClientHook(hook ClientHook) *clientHook {
	h := &clientHook{
		ClientHook: hook,
		refs:       1,
		done:       make(chan struct{}),
	}
	if h.Resolved() == nil {
		h.resolved = true
		h.resolvedHook = h
	}
	return h
}

// A ClientHook represents a Cap'n Proto capability.  Application code
// should not pass around ClientHooks; applications should pass around
// Clients.  A ClientHook must be safe to use from multiple goroutines.
type ClientHook interface {
	// Call starts executing a method and returns an answer that will hold
	// the resulting struct.  The call's parameters must be placed before
	// Call() returns.
	//
	// Calls are delivered to the capability in the order they are made.
	// This guarantee is based on the concept of a capability
	// acknowledging delivery of a call: this is specific to an
	// implementation of ClientHook.  A type that implements ClientHook
	// must guarantee that if foo() then bar() is called on a client, that
	// acknowledging foo() happens before acknowledging bar().
	Call(ctx context.Context, call *Call) Answer

	// If this client is a promise, then Resolve returns a channel that
	// is closed when the promise resolves.  Otherwise, Resolve returns
	// a nil channel.  Resolved must return the same channel on every
	// call.
	//
	// Once a client resolves to another client, calls to Call and Brand
	// must be identical to calling these methods on the resolved
	// client.
	Resolved() <-chan struct{}

	// ResolvedClient returns the resolved client.  The receiver owns the
	// resolved client reference: that is, the caller must not call Close
	// on it.  ResolvedClient must only be called after the Resolved
	// channel is closed.
	ResolvedClient() *Client

	// Brand returns an implementation-specific value.  This can be used
	// to introspect and identify kinds of clients.
	Brand() interface{}

	// Close releases any resources associated with this capability.
	// The behavior of calling any methods on the receiver after calling
	// Close is undefined.
	Close() error
}

// The Call type holds the record for an outgoing interface call.
type Call struct {
	// Method is the interface ID and method ID, along with the optional name,
	// of the method to call.
	Method Method

	// Params is a struct containing parameters for the call.
	// This should be set when the RPC system receives a call for an
	// exported interface.  It is mutually exclusive with ParamsFunc
	// and ParamsSize.
	Params Struct
	// ParamsFunc is a function that populates an allocated struct with
	// the parameters for the call.  ParamsSize determines the size of the
	// struct to allocate.  This is used when application code is using a
	// client.  These settings should be set together; they are mutually
	// exclusive with Params.
	ParamsFunc func(Struct) error
	ParamsSize ObjectSize

	// Options passes RPC-specific options for the call.
	Options CallOptions
}

// Copy clones a call, ensuring that its Params are placed.
// If Call.ParamsFunc is nil, then the same Call will be returned.
func (call *Call) Copy(s *Segment) (*Call, error) {
	if call.ParamsFunc == nil {
		return call, nil
	}
	p, err := call.PlaceParams(s)
	if err != nil {
		return nil, err
	}
	return &Call{
		Method:  call.Method,
		Params:  p,
		Options: call.Options,
	}, nil
}

// PlaceParams returns the parameters struct, allocating it inside
// segment s as necessary.  If s is nil, a new single-segment message
// is allocated.
func (call *Call) PlaceParams(s *Segment) (Struct, error) {
	if call.ParamsFunc == nil {
		return call.Params, nil
	}
	if s == nil {
		var err error
		_, s, err = NewMessage(SingleSegment(nil))
		if err != nil {
			return Struct{}, err
		}
	}
	p, err := NewStruct(s, call.ParamsSize)
	if err != nil {
		return Struct{}, nil
	}
	err = call.ParamsFunc(p)
	return p, err
}

// CallOptions holds RPC-specific options for an interface call.
// Its usage is similar to the values in context.Context, but is only
// used for a single call: its values are not intended to propagate to
// other callees.  An example of an option would be the
// Call.sendResultsTo field in rpc.capnp.
type CallOptions struct {
	m map[interface{}]interface{}
}

// NewCallOptions builds a CallOptions value from a list of individual options.
func NewCallOptions(opts []CallOption) CallOptions {
	co := CallOptions{make(map[interface{}]interface{})}
	for _, o := range opts {
		o.f(co)
	}
	return co
}

// Value retrieves the value associated with the options for this key,
// or nil if no value is associated with this key.
func (co CallOptions) Value(key interface{}) interface{} {
	return co.m[key]
}

// With creates a copy of the CallOptions value with other options applied.
func (co CallOptions) With(opts []CallOption) CallOptions {
	newopts := CallOptions{make(map[interface{}]interface{})}
	for k, v := range co.m {
		newopts.m[k] = v
	}
	for _, o := range opts {
		o.f(newopts)
	}
	return newopts
}

// A CallOption is a function that modifies options on an interface call.
type CallOption struct {
	f func(CallOptions)
}

// SetOptionValue returns a call option that associates a value to an
// option key.  This can be retrieved later with CallOptions.Value.
func SetOptionValue(key, value interface{}) CallOption {
	return CallOption{func(co CallOptions) {
		co.m[key] = value
	}}
}

// An Answer is the deferred result of a client call, which is usually wrapped by a Pipeline.
// An Answer must be safe to use from multiple goroutines.
type Answer interface {
	// Struct waits until the call is finished and returns the result.
	Struct() (Struct, error)

	// Done returns a channel that is closed when call is finished.
	// Done must always return the same channel.
	Done() <-chan struct{}

	// PipelineCall sends a call to the Client identified by the transform.
	// Answers may have a more efficient way of doing this than waiting
	// for the call to be finished (promise pipelining).
	PipelineCall(ctx context.Context, transform []PipelineOp, call *Call) Answer

	Close() error
}

// A Pipeline is a generic wrapper for an answer.
// It is safe to use from multiple goroutines.
type Pipeline struct {
	answer Answer
	parent *Pipeline
	pool   *pipelineClientPool
	op     PipelineOp
}

// NewPipeline returns a new pipeline based on an answer.
func NewPipeline(ans Answer) (_ *Pipeline, close func()) {
	return &Pipeline{answer: ans}
}

// Answer returns the answer the pipeline is derived from.
func (p *Pipeline) Answer() Answer {
	return p.answer
}

// Transform returns the operations needed to transform the root answer
// into the value p represents.
func (p *Pipeline) Transform() []PipelineOp {
	n := 0
	for q := p; q.parent != nil; q = q.parent {
		n++
	}
	xform := make([]PipelineOp, n)
	for i, q := n-1, p; q.parent != nil; i, q = i-1, q.parent {
		xform[i] = q.op
	}
	return xform
}

// Struct waits until the answer is resolved and returns the struct
// this pipeline represents.
func (p *Pipeline) Struct() (Struct, error) {
	s, err := p.answer.Struct()
	if err != nil {
		return Struct{}, err
	}
	ptr, err := Transform(s.ToPtr(), p.Transform())
	if err != nil {
		return Struct{}, err
	}
	return ptr.Struct(), nil
}

// Client returns the client version of p.
func (p *Pipeline) Client() *Client {
	// TODO(soon):
	return NewClient((*pipelineClient)(p))
}

// GetPipeline returns a derived pipeline which yields the pointer field given.
func (p *Pipeline) GetPipeline(off uint16) *Pipeline {
	return p.GetPipelineDefault(off, nil)
}

// GetPipelineDefault returns a derived pipeline which yields the pointer field given,
// defaulting to the value given.
func (p *Pipeline) GetPipelineDefault(off uint16, def []byte) *Pipeline {
	return &Pipeline{
		answer: p.answer,
		parent: p,
		op: PipelineOp{
			Field:        off,
			DefaultValue: def,
		},
	}
}

type pipelineClientPool struct {
	ans Answer

	mu      sync.Mutex
	clients []pipelineClientEntry
}

func newPipelineClientPool(ans Answer) *pipelineClientPool {
	pool := &pipelineClientPool{ans: ans}
	select {
	case <-ans.Done():
	default:
		go func() {
			<-ans.Done()
			defer pool.mu.Unlock()
			pool.mu.Lock()
			for _, c := range pool.clients {
				c.Close()
			}
			pool.clients = nil
		}()
	}
	return pool
}

func (pool *pipelineClientPool) get(transform []PipelineOp) *Client {
	defer pool.mu.Unlock()
	pool.mu.Lock()
	select {
	case <-pool.ans.Done():
		s, err := pool.ans.Struct()
		return clientFromResolution(transform, s.ToPtr(), err)
	default:
		i := sort.Search(len(pool.clients), func(i int) bool {
			return !transformLess(pool.clients[i].transform, transform)
		})
		if i < len(pool.clients) && transformEqual(transform, pool.clients[i].transform) {
			return pool.clients[i]
		}
		pool.clients = append(pool.clients, pipelineClientEntry{})
		copy(pool.clients[i+1:], pool.clients[i:])
		c := NewClient(&pipelineClient{
			ans:       pool.ans,
			transform: transform,
		})
		pool.clients[i] = pipelineClientEntry{
			transform: cloneTransformPath(transform),
			client:    c,
		}
		return c
	}
}

type pipelineClientEntry struct {
	transform []PipelineOp
	client    *Client
}

// pipelineClient implements Client by calling to the pipeline's answer.
type pipelineClient struct {
	ans       Answer
	transform []PipelineOp

	client *Client // must only be accessed after calling join()
}

func (pc *pipelineClient) join() {
	pc.once.Do(func() {
	})
}

// Call calls Answer.PipelineCall with the pipeline's transform.
func (pc *pipelineClient) Call(ctx context.Context, call *Call) Answer {
	return pc.ans.PipelineCall(ctx, pc.transform, call)
}

func (pc *pipelineClient) Resolved() <-chan struct{} {
	return pc.ans.Done()
}

func (pc *pipelineClient) ResolvedClient() *Client {
	pc.join()
	return pc.client
}

func (pc *pipelineClient) Brand() interface{} {
	select {
	case <-pc.p.answer.Done():
		pc.join()
		return pc.client.Brand()
	default:
		return nil
	}
}

// Close waits until the call is completed and calls Close on the client
// found at the pipeline's transform.
func (pc *pipelineClient) Close() error {
	pc.join()
	return pc.client.Close()
}

// A PipelineOp describes a step in transforming a pipeline.
// It maps closely with the PromisedAnswer.Op struct in rpc.capnp.
type PipelineOp struct {
	Field        uint16
	DefaultValue []byte
}

// String returns a human-readable description of op.
func (op PipelineOp) String() string {
	s := make([]byte, 0, 32)
	s = append(s, "get field "...)
	s = strconv.AppendInt(s, int64(op.Field), 10)
	if op.DefaultValue == nil {
		return string(s)
	}
	s = append(s, " with default"...)
	return string(s)
}

// A Method identifies a method along with an optional human-readable
// description of the method.
type Method struct {
	InterfaceID uint64
	MethodID    uint16

	// Canonical name of the interface.  May be empty.
	InterfaceName string
	// Method name as it appears in the schema.  May be empty.
	MethodName string
}

// String returns a formatted string containing the interface name or
// the method name if present, otherwise it uses the raw IDs.
// This is suitable for use in error messages and logs.
func (m *Method) String() string {
	buf := make([]byte, 0, 128)
	if m.InterfaceName == "" {
		buf = append(buf, '@', '0', 'x')
		buf = strconv.AppendUint(buf, m.InterfaceID, 16)
	} else {
		buf = append(buf, m.InterfaceName...)
	}
	buf = append(buf, '.')
	if m.MethodName == "" {
		buf = append(buf, '@')
		buf = strconv.AppendUint(buf, uint64(m.MethodID), 10)
	} else {
		buf = append(buf, m.MethodName...)
	}
	return string(buf)
}

// Transform applies a sequence of pipeline operations to a pointer
// and returns the result.
func Transform(p Ptr, transform []PipelineOp) (Ptr, error) {
	n := len(transform)
	if n == 0 {
		return p, nil
	}
	s := p.Struct()
	for _, op := range transform[:n-1] {
		field, err := s.Ptr(op.Field)
		if err != nil {
			return Ptr{}, err
		}
		s, err = field.StructDefault(op.DefaultValue)
		if err != nil {
			return Ptr{}, err
		}
	}
	op := transform[n-1]
	p, err := s.Ptr(op.Field)
	if err != nil {
		return Ptr{}, err
	}
	if op.DefaultValue != nil {
		p, err = p.Default(op.DefaultValue)
	}
	return p, err
}

func transformLess(t, u []PipelineOp) bool {
	for i := 0; i < len(t) && i < len(u); i++ {
		if t[i].Field != u[i].Field {
			return t[i].Field < u[i].Field
		}
	}
	return len(t) < len(u)
}

func transformEqual(t, u []PipelineOp) bool {
	if len(t) != len(u) {
		return false
	}
	for i := range t {
		if t[i].Field != u[i].Field {
			return false
		}
	}
	return true
}

func cloneTransformPath(t []PipelineOp) []PipelineOp {
	u := make([]PipelineOp, len(t))
	for i := range t {
		u[i].Field = t[i].Field
	}
	return u
}

// clientFromResolution retrieves a client from a resolved pointer and error
// by applying a transform.
func clientFromResolution(transform []capnp.PipelineOp, obj capnp.Ptr, err error) *capnp.Client {
	if err != nil {
		return ErrorClient(err)
	}
	out, err := capnp.Transform(obj, transform)
	if err != nil {
		return ErrorClient(err)
	}
	return out.Interface().Client()
}

type immediateAnswer struct {
	s Struct
}

// ImmediateAnswer returns an Answer that accesses s.
func ImmediateAnswer(s Struct) Answer {
	return immediateAnswer{s}
}

func (ans immediateAnswer) Struct() (Struct, error) {
	return ans.s, nil
}

func (ans immediateAnswer) Done() <-chan struct{} {
	return closedSignal
}

func (ans immediateAnswer) findClient(transform []PipelineOp) *Client {
	p, err := Transform(ans.s.ToPtr(), transform)
	if err != nil {
		return ErrorClient(err)
	}
	return p.Interface().Client()
}

func (ans immediateAnswer) PipelineCall(ctx context.Context, transform []PipelineOp, call *Call) Answer {
	return ans.findClient(transform).Call(ctx, call)
}

type errorAnswer struct {
	e error
}

// ErrorAnswer returns a Answer that always returns error e.
func ErrorAnswer(e error) Answer {
	return errorAnswer{e}
}

func (ans errorAnswer) Struct() (Struct, error) {
	return Struct{}, ans.e
}

func (ans errorAnswer) Done() <-chan struct{} {
	return closedSignal
}

func (ans errorAnswer) PipelineCall(context.Context, []PipelineOp, *Call) Answer {
	return ans
}

type errorClient struct {
	e error
}

// ErrorClient returns a Client that always returns error e.
//
// While this does create a new reference, it is not necessary for the caller
// to Close an ErrorClient.  An ErrorClient is similar to a nil Client in this
// respect.
func ErrorClient(e error) *Client {
	return NewClient(&errorClient{e})
}

func (ec *errorClient) Call(context.Context, *Call) Answer {
	return ErrorAnswer(ec.e)
}

func (ec *errorClient) Resolved() <-chan struct{} {
	return nil
}

func (ec *errorClient) ResolvedClient() *Client {
	panic("*errorClient.ResolvedClient")
}

func (ec *errorClient) Brand() interface{} {
	return ec
}

func (ec *errorClient) Close() error {
	return nil
}

// IsErrorClient reports whether c was created with ErrorClient.
func IsErrorClient(c *Client) bool {
	_, ok := c.Brand().(*errorClient)
	return ok
}

// MethodError is an error on an associated method.
type MethodError struct {
	Method *Method
	Err    error
}

// Error returns the method name concatenated with the error string.
func (e *MethodError) Error() string {
	return e.Method.String() + ": " + e.Err.Error()
}

// ErrUnimplemented is the error returned when a method is called on
// a server that does not implement the method.
var ErrUnimplemented = errors.New("capnp: method not implemented")

// IsUnimplemented reports whether e indicates an unimplemented method error.
func IsUnimplemented(e error) bool {
	if me, ok := e.(*MethodError); ok {
		e = me.Err
	}
	return e == ErrUnimplemented
}

var closedSignal = newClosedSignal()

func newClosedSignal() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}
