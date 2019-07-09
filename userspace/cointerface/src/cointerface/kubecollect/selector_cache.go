package kubecollect

import (
	"sync"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

// Interface needed by a k8s resource to use a selectorCache
type cacheableSelector interface {
	GetUID() types.UID
	Selector() labels.Selector
	// Some resources are optionally filtered out so they don't send any
	// congroup updates, so don't cache their selectors
	Filtered() bool
	// Only cache selectors for resources with active pod children.
	//
	// When the value goes from >0 to zero, e.g. an rs is scaled down,
	// resources should set !sameLinks and remove the selector from the
	// the cache in order to reclaim memory.
	//
	// When the value goes from zero to >0, resources should also set
	// !sameLinks, although it's not mandatory as the selector can be
	// generated on the next Get() call. It makes for simpler code, and
	// it puts the cpu cost of creating the selector on the parent's
	// goroutine instead of the busier pod goroutine.
	ActiveChildren() int32
}


// https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/
//
// One of the ways to do parent<->child matching is by comparing the
// labels of the child object (usually a pod) to the selector of the
// parent (e.g. service). Selectors are stored as strings in the parent
// object's spec, and converting that string to a labels.Selector object
// can be very cpu intensive. A parent objects's selector will rarely
// change during its lifetime, but it will be needed for matching every
// time a potential child object is added. Specifically, every pod
// update with !sameLinks is a potential child of all parent types.
//
// The selectorCache lets each object type store those labels.Selector
// objects and avoid repeatedly paying the cpu cost of creating the
// selector object. In theory it comes at the cost of memory, but
// observed memory usage hasn't change significantly, likely because of
// gc inefficiency with constantly creating & destroying objects.
//
// The caller is responsible for calling Remove() when objects are deleted
// to avoid leaking. It's safe to call Remove() even if we don't have a
// selector cached, so types should always call it in their DeleteFunc.
type selectorCache struct {
	selectors map[types.UID]labels.Selector
	cacheMutex sync.RWMutex
}

func newSelectorCache() *selectorCache {
	return &selectorCache{
		selectors: make(map[types.UID]labels.Selector),
	}
}

func (c *selectorCache) Add(obj cacheableSelector) labels.Selector {
	// This is the cpu-heavy piece, so keep it outside the lock
	sel := obj.Selector()

	c.cacheMutex.Lock()
	// It's possible another thread added the selector between
	// locks, but checking requires a second lookup in most cases
	// so always copy the newly created selector
	c.selectors[obj.GetUID()] = sel
	c.cacheMutex.Unlock()
	return sel
}

func (c *selectorCache) Remove(obj cacheableSelector) {
	c.cacheMutex.Lock()
	delete(c.selectors, obj.GetUID())
	c.cacheMutex.Unlock()
}

func (c *selectorCache) Get(obj cacheableSelector) (labels.Selector, bool) {
	// Objects with no possible children never go in the cache to keep
	// memory consumption down
	if obj.Filtered() || obj.ActiveChildren() == 0 {
		var zeroVal labels.Selector
		return zeroVal, false
	}

	c.cacheMutex.RLock()
	s, ok := c.selectors[obj.GetUID()]
	c.cacheMutex.RUnlock()

	if !ok {
		s = c.Add(obj)
	}
	return s, true
}

func (c *selectorCache) Update(obj cacheableSelector) {
	if obj.Filtered() || obj.ActiveChildren() == 0 {
		c.Remove(obj)
	} else {
		c.Add(obj)
	}
}
