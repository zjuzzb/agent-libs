package kubecollect

import (
	"reflect"
	"testing"
	. "test_helpers"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
)

type coMockCacheable struct {
	gen int
	uid types.UID
	filter bool
}

func newCoMockCacheable(u types.UID) *coMockCacheable {
	return &coMockCacheable{
		gen: 0,
		uid: u,
		filter: false,
	}
}

func (obj coMockCacheable) GenCount() int {
	return obj.gen
}

func (obj coMockCacheable) GetUID() types.UID {
	return obj.uid
}

func (obj *coMockCacheable) Selector() labels.Selector {
	obj.gen++
	s := labels.Everything()
	return s
}

func (obj coMockCacheable) Filtered() bool {
	return obj.filter
}

func (obj coMockCacheable) ActiveChildren() int32 {
	return 1
}

func TestSelectorCache(t *testing.T) {
	cache := newSelectorCache()
	obj1 := newCoMockCacheable("abcdef")
	obj2 := newCoMockCacheable("fedcba")

	// Add obj1 and check that we have the correct selector
	cache.Add(obj1)
	sel, exists := cache.Get(obj1)
	AssertEqual(t, obj1.GenCount(), 1)
	AssertEqual(t, len(cache.selectors), 1)
	AssertEqual(t, exists, true)
	if !reflect.DeepEqual(sel, labels.Everything()) {
		t.Log("Incorrect selector in cache")
		t.Fail()
	}

	// Remove a non-existent obj2
	cache.Remove(obj2)
	AssertEqual(t, 0, obj2.GenCount())
	AssertEqual(t, 1, len(cache.selectors))

	// Fail to Get() a filtered obj2
	obj2.filter = true
	sel, exists = cache.Get(obj2)
	AssertEqual(t, 0, obj2.GenCount())
	AssertEqual(t, 1, len(cache.selectors))
	AssertEqual(t, false, exists)

	// Succeed at Get()'ing an unfiltered obj2
	obj2.filter = false
	sel, exists = cache.Get(obj2)
	AssertEqual(t, 1, obj2.GenCount())
	AssertEqual(t, 2, len(cache.selectors))
	AssertEqual(t, true, exists)

	// Update an existing obj2, generate the selector again
	cache.Update(obj2)
	AssertEqual(t, 2, obj2.GenCount())
	AssertEqual(t, 2, len(cache.selectors))

	// Update a filtered obj2 and see it get removed
	obj2.filter = true
	cache.Update(obj2)
	AssertEqual(t, 2, obj2.GenCount())
	AssertEqual(t, 1, len(cache.selectors))

	// Update again with filtered obj2 to confirm it does nothing
	cache.Update(obj2)
	AssertEqual(t, 2, obj2.GenCount())
	AssertEqual(t, 1, len(cache.selectors))

	// Make a bunch of cached Get() calls before removing obj1
	for ii := 0; ii < 10; ii++ {
		cache.Get(obj1)
	}
	cache.Remove(obj1)
	AssertEqual(t, 1, obj1.GenCount())
	AssertEqual(t, 0, len(cache.selectors))
}
