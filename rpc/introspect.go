package rpc

import (
	"zombiezen.com/go/capnproto2"
	"zombiezen.com/go/capnproto2/internal/fulfiller"
	"zombiezen.com/go/capnproto2/rpc/internal/refcount"
	rpccapnp "zombiezen.com/go/capnproto2/std/capnp/rpc"
)

// While the code below looks repetitive, resist the urge to refactor.
// Each operation is distinct in assumptions it can make about
// particular cases, and there isn't a convenient type signature that
// fits all cases.

// lockedCall is used to make a call to an arbitrary client while
// holding onto c.mu.  Since the client could point back to c, naively
// calling c.Call could deadlock.
func (c *Conn) lockedCall(client capnp.Client, cl *capnp.Call) capnp.Answer {
dig:
	for client := client; ; {
		switch curr := client.(type) {
		case *importClient:
			if curr.conn != c {
				// This doesn't use our conn's lock, so it is safe to call.
				return curr.Call(cl)
			}
			return curr.lockedCall(cl)
		case *fulfiller.EmbargoClient:
			if ans := curr.TryQueue(cl); ans != nil {
				return ans
			}
			client = curr.Client()
		case *refcount.Ref:
			client = curr.Client()
		case *embargoClient:
			if ans := curr.tryQueue(cl); ans != nil {
				return ans
			}
			client = curr.client
		case *queueClient:
			if ans := curr.tryQueue(cl); ans != nil {
				return ans
			}
			client = curr.client
		case *localAnswerClient:
			if ans := curr.tryQueue(cl); ans != nil {
				return ans
			}
			obj, err, _ := curr.a.peek()
			client = clientFromResolution(curr.transform, obj, err)
		case *capnp.PipelineClient:
			p := (*capnp.Pipeline)(curr)
			ans := p.Answer()
			transform := p.Transform()
			if capnp.IsFixedAnswer(ans) {
				s, err := ans.Struct()
				client = clientFromResolution(transform, s.ToPtr(), err)
				continue
			}
			switch ans := ans.(type) {
			case *fulfiller.Fulfiller:
				ap := ans.Peek()
				if ap == nil {
					break dig
				}
				s, err := ap.Struct()
				client = clientFromResolution(transform, s.ToPtr(), err)
			case *question:
				if ans.conn != c {
					// This doesn't use our conn's lock, so it is safe to call.
					return ans.PipelineCall(transform, cl)
				}
				return ans.lockedPipelineCall(transform, cl)
			default:
				break dig
			}
		default:
			break dig
		}
	}

	// TODO(light): Add a CallOption that signals to bypass sync.
	// The above hack works in *most* cases.
	//
	// If your code is deadlocking here, you've hit the edge of the
	// compromise between these three goals:
	// 1) Package capnp is loosely coupled with package rpc
	// 2) Arbitrary implementations of Client may exist
	// 3) Local E-order must be preserved
	//
	// #3 is the one that creates a deadlock, since application code must
	// acquire the connection mutex to preserve order of delivery.  You
	// can't really overcome this without breaking one of the first two
	// constraints.
	//
	// To avoid #2 as much as possible, implementing Client is discouraged
	// by several docs.
	return client.Call(cl)
}

// descriptorForClient fills desc for client, adding it to the export
// table if necessary.  The caller must be holding onto c.mu.
func (c *Conn) descriptorForClient(desc rpccapnp.CapDescriptor, client capnp.Client) error {
dig:
	for client := client; ; {
		switch ct := client.(type) {
		case *importClient:
			if ct.conn != c {
				break dig
			}
			desc.SetReceiverHosted(uint32(ct.id))
			return nil
		case *fulfiller.EmbargoClient:
			client = ct.Client()
			if client == nil {
				break dig
			}
		case *refcount.Ref:
			client = ct.Client()
		case *embargoClient:
			ct.mu.RLock()
			ok := ct.isPassthrough()
			ct.mu.RUnlock()
			if !ok {
				break dig
			}
			client = ct.client
		case *queueClient:
			ct.mu.RLock()
			ok := ct.isPassthrough()
			ct.mu.RUnlock()
			if !ok {
				break dig
			}
			client = ct.client
		case *localAnswerClient:
			obj, err, ok := ct.a.peek()
			if !ok {
				break dig
			}
			client = clientFromResolution(ct.transform, obj, err)
		case *capnp.PipelineClient:
			p := (*capnp.Pipeline)(ct)
			ans := p.Answer()
			transform := p.Transform()
			if capnp.IsFixedAnswer(ans) {
				s, err := ans.Struct()
				client = clientFromResolution(transform, s.ToPtr(), err)
				continue
			}
			switch ans := ans.(type) {
			case *fulfiller.Fulfiller:
				ap := ans.Peek()
				if ap == nil {
					break dig
				}
				s, err := ap.Struct()
				client = clientFromResolution(transform, s.ToPtr(), err)
			case *question:
				ans.mu.RLock()
				obj, err, state := ans.obj, ans.err, ans.state
				ans.mu.RUnlock()
				if state != questionInProgress {
					client = clientFromResolution(transform, obj, err)
					continue
				}
				if ans.conn != c {
					break dig
				}
				a, err := desc.NewReceiverAnswer()
				if err != nil {
					return err
				}
				a.SetQuestionId(uint32(ans.id))
				err = transformToPromisedAnswer(desc.Segment(), a, p.Transform())
				if err != nil {
					return err
				}
				return nil
			default:
				break dig
			}
		default:
			break dig
		}
	}

	id := c.addExport(client)
	desc.SetSenderHosted(uint32(id))
	return nil
}

// isImport returns the underlying import if client represents an import
// or nil otherwise.
func isImport(client capnp.Client) *importClient {
	for {
		switch curr := client.(type) {
		case *importClient:
			return curr
		case *fulfiller.EmbargoClient:
			client = curr.Client()
			if client == nil {
				return nil
			}
		case *refcount.Ref:
			client = curr.Client()
		case *embargoClient:
			curr.mu.RLock()
			ok := curr.isPassthrough()
			curr.mu.RUnlock()
			if !ok {
				return nil
			}
			client = curr.client
		case *queueClient:
			curr.mu.RLock()
			ok := curr.isPassthrough()
			curr.mu.RUnlock()
			if !ok {
				return nil
			}
			client = curr.client
		case *localAnswerClient:
			obj, err, ok := curr.a.peek()
			if !ok {
				return nil
			}
			client = clientFromResolution(curr.transform, obj, err)
		case *capnp.PipelineClient:
			p := (*capnp.Pipeline)(curr)
			ans := p.Answer()
			if capnp.IsFixedAnswer(ans) {
				s, err := ans.Struct()
				client = clientFromResolution(p.Transform(), s.ToPtr(), err)
				continue
			}
			switch ans := ans.(type) {
			case *fulfiller.Fulfiller:
				ap := ans.Peek()
				if ap == nil {
					return nil
				}
				s, err := ap.Struct()
				client = clientFromResolution(p.Transform(), s.ToPtr(), err)
			case *question:
				ans.mu.RLock()
				obj, err, state := ans.obj, ans.err, ans.state
				ans.mu.RUnlock()
				if state != questionResolved {
					return nil
				}
				client = clientFromResolution(p.Transform(), obj, err)
			default:
				return nil
			}
		default:
			return nil
		}
	}
}
