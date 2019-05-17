package kubecollect

import (
	"context"
	"math/rand"
	"strconv"
	"testing"
	"time"
	
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	
	"cointerface/draiosproto"
	"cointerface/sdc_internal"
	
	"github.com/gogo/protobuf/proto"	
)

// Return a pointer to a randomized resource list
// that we create. In the real world you could have
// multiple resource types; each belonging to different
// groupversions.
// But until we have support for different grouoversions;
// this serves as a good replica. 
func createAPIResourceList(listSize int) (resourceList *v1meta.APIResourceList) {

	resourceTypes := []string {
		"cronjobs", "daemonsets", "deployments", "horizontalpodautoscalers",
		"ingress", "jobs","namespaces","nodes","pods","replicasets",
		"replicationcontrollers", "resourcequotas","services","statefulsets"}

	// Make random indexes for above resourceTypes
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	
	indexes := make([]int, listSize)
	for i := 0; i < listSize; i++ {
		indexes[i]= r1.Intn(len(resourceTypes))
	}

	// Create output APIResourceList
	orig := &v1meta.APIResourceList {
		GroupVersion: "core/v1",
	}
	
	for _, ind := range indexes {
		orig.APIResources = append(orig.APIResources , v1meta.APIResource{
			Name: resourceTypes[ind],
		})
	}

	return orig
}

// Func to test if the resourceOrder Vector contains no repeats
func checkNoRepeatsHelper(t *testing.T, resourceOrder []string, expected bool) {

	resourceMap := make(map[string]bool)

	res := true
	
	for _, resourceType := range resourceOrder {
		if(resourceMap[resourceType]) {
			res = false
			break
		}
		resourceMap[resourceType] = true
	}
	
	if res != expected {
		t.Error("There are repeats in the vector")
		t.Fail()
	}
	
}


func checkNodesAndNamespacesFirstHelper(t *testing.T, resourceOrder []string, expected bool) {

	namespacesOrNodesEnd := false
	res := true
	for _, resource := range resourceOrder {
		if(resource == "nodes" || resource == "namespaces") {
			// Let's hope this isn't seen after we saw
			// a non-node or non-namespace resource
			if(namespacesOrNodesEnd) {
				res = false
				break
			}
		} else {
			namespacesOrNodesEnd = true
		}
	}

	if res != expected {
		t.Error("namespaces or nodes isn't beginning of the list")
		t.Fail()
	}
	
}

// basic test to test above helper method
func TestCheckNodesAndNamespacesFirstHelper(t *testing.T) {

	// Test a pass case
	resOrderPass := []string{"namespaces","nodes", "namespaces", "nodes", "pods", "replicasets"}
	checkNodesAndNamespacesFirstHelper(t, resOrderPass, true)

	// test a fail case
	resOrderFail := []string{"namespaces", "nodes", "pods", "nodes"}
	checkNodesAndNamespacesFirstHelper(t, resOrderFail, false)	
}

// Test using actual APIResourceList
func TestBasicResourceOrdering(t *testing.T) {

	// Create 2 different sized resourcelists and
	// test that either nodes or namespaces are always first
	resourceList := []*v1meta.APIResourceList{ createAPIResourceList(rand.Intn(20)),
		createAPIResourceList(rand.Intn(30))}

	resourceOrder := getResourceTypes(resourceList, nil)

	checkNoRepeatsHelper(t, resourceOrder, true)
	
	checkNodesAndNamespacesFirstHelper(t ,resourceOrder, true)

	// Ensure you add some namespaces or nodes to the end and still it doesn't fail
	for _, resource := range resourceList {
		resource.APIResources = append(resource.APIResources, v1meta.APIResource{
			Name: "nodes",
		})
		resource.APIResources = append(resource.APIResources, v1meta.APIResource{
			Name: "namespaces",
		})
	}

	resourceOrderNew := getResourceTypes(resourceList, nil)
	checkNoRepeatsHelper(t, resourceOrderNew, true)
	checkNodesAndNamespacesFirstHelper(t ,resourceOrderNew, true)	
}

// This function is a helper to test no Cronjob exists in the input list
func checkNoCronjobsExistHelper(t *testing.T, resourceOrder []string, expected bool) {

	res := true
	for _, str := range resourceOrder {
		if str == "cronjobs" {
			res = false
			break
		}
	}

	if res != expected {
		t.Error("Cronjob exists when it shouldn't")
		t.Fail()
	}
}

// Actual function to test Cronjob filtering based
// on value of "GroupVersion"
func TestCronjobExistsInResourceOrder(t *testing.T) {
	// Create resourcelists and add Cronjobs to it and
	// test that it shows up when groupVersion is correct
	resourceList := []*v1meta.APIResourceList{ createAPIResourceList(rand.Intn(10)) }
	resourceList[0].APIResources = append(resourceList[0].APIResources, v1meta.APIResource{
		Name: "cronjobs",
	})

	resourceOrderWithOutCronjobs := getResourceTypes(resourceList, nil)
	
	// Since group version by default is
	// v1ForTesting, no cronjobs should be added
	checkNoCronjobsExistHelper(t, resourceOrderWithOutCronjobs, true)

	// Now modify groupversion to the supported value and check cronjobs exist
	resourceList[0].GroupVersion = "batch/v2alpha1"
	
	resourceOrderWithCronjobs := getResourceTypes(resourceList, nil)
	checkNoCronjobsExistHelper(t,resourceOrderWithCronjobs, false)
}

// This function is a helper to test if a given type exists
func checkExtraResourceTypesHelper(t *testing.T, resources []string, rt string, expected bool) {
	res := false
	for _, str := range resources {
		if str == rt {
			res = true
			break
		}
	}

	if res != expected {
		if expected {
			t.Error(rt + " doesn't exist when it should")
		} else {
			t.Error(rt + " exists when it shouldn't")
		}
		t.Fail()
	}
}

func TestResourceTypeIncludes(t *testing.T) {
	// Create resourcelists and ensure services, hpas and resourcequotas exist
	resourceList := []*v1meta.APIResourceList{ createAPIResourceList(rand.Intn(10)) }
	resourceList[0].APIResources = append(resourceList[0].APIResources,
		v1meta.APIResource{ Name: "services", },
		v1meta.APIResource{ Name: "horizontalpodautoscalers", },
		v1meta.APIResource{ Name: "resourcequotas", } )

	resourceswithoutextras := getResourceTypes(resourceList, nil)

	// Since extras aren't taken by default, these should not exist
	checkExtraResourceTypesHelper(t, resourceswithoutextras, "services", false)
	checkExtraResourceTypesHelper(t, resourceswithoutextras, "horizontalpodautoscalers", false)
	checkExtraResourceTypesHelper(t, resourceswithoutextras, "resourcequotas", false)

	// Now add them to the include list and they should now exist
	includeList := []string{ "services", "horizontalpodautoscalers", "resourcequotas" }

	resourceswithextras := getResourceTypes(resourceList, includeList)
	checkExtraResourceTypesHelper(t, resourceswithextras, "services", true)
	checkExtraResourceTypesHelper(t, resourceswithextras, "horizontalpodautoscalers", true)
	checkExtraResourceTypesHelper(t, resourceswithextras, "resourcequotas", true)
}

// Helper method that sets up the chan and context for
// many of the Test methods below.
func setupChanTestInfra() (
	chan draiosproto.CongroupUpdateEvent,
	chan sdc_internal.ArrayCongroupUpdateEvent,
	context.Context) {
	evtChan := make(chan draiosproto.CongroupUpdateEvent, 100)
	evtArrChan := make(chan sdc_internal.ArrayCongroupUpdateEvent, 1)
	ctx, _ := context.WithCancel(context.Background())

	return evtChan, evtArrChan, ctx
}

// UT that tests the working of batchEvents method in client.go
// Also tests whether the server.go can receive all the events correctly
// This mimicks a bit of code in server.go to achieve this.
// Would be nice if we can UT other methods in client.go and server.go
func TestEvtArrayChanEvents(t* testing.T) {

	// This is a test involving goroutines and channels.
	// Skip it during normal operation
	// Ideally the cointerface developer will comment this
	// during sandbox testing.
	// FUTURE Plan: Ideally we would split our testing into
	// tests with shorting and we would do our compile time
	// tests with shorting and then have a test suite that
	// would run without shorting. (SMAGENT-1521)
	t.Skip("skipping test for now during compile time.")
	
	evtChan , evtArrChan, ctx := setupChanTestInfra()

	numNamespaces := 1000
	queueLen := uint32(0)

	go startNamespaceSends(evtChan, numNamespaces)
	
	// Call the batchEvents in client.go to UT it. Use defaults for batchsizes (for now)
	go batchEvents(ctx, evtArrChan, evtChan, uint32(100), uint32(100), &queueLen)

	nameSpace := 0

	for {
		evtArray, ok := <-evtArrChan
		if !ok {
			break // No more evtArray
		} 
		// Do a check of events
		for _, item := range evtArray.Events {
			objId, err := strconv.Atoi(*(item.Object.Uid.Id))
			if err != nil {
				t.Error("Error during string to int conversion")
				t.Fail()
			}
			if(nameSpace != objId) {
				t.Errorf("Mis-match in namespace check: %v and %v",nameSpace, objId)
				t.Fail()
			}
			nameSpace = nameSpace + 1
		}
	}
	
	if(nameSpace != numNamespaces) {
		t.Error("Failed to receive all namespaces")
		t.Fail()
	}
}

// Test the method DrainChan on a chan of type evtChan
func TestDrainChanOnEvtChan(t* testing.T){
	// This is a test involving goroutines and channels.
	// Skip it during normal operation
	t.Skip("skipping test for now during compile time.")
	
	evtChan , _, _ := setupChanTestInfra()

	go startNamespaceSends(evtChan, 200)
	
	// Test the DrainChan by draining on the evtChan (receive only chan)
	DrainChan((<-chan draiosproto.CongroupUpdateEvent)(evtChan))

	// Test that the chan is empty
	_, ok := <-evtChan
	if ok {
		t.Error("The evtChan should be empty by now.")
		t.Fail()
	}

}

// Test the method DrainChan on a chan of type evtArrChan
func TestDrainChanOnEvtArrayChan(t* testing.T){
	// This is a test involving goroutines and channels.
	// Skip it during normal operation
	t.Skip("skipping test for now during compile time.")
	
	evtChan , evtArrChan, ctx := setupChanTestInfra()
	queueLen := uint32(0)

	// Now let's do this same test with batchEvents and
	// call drainchan on evtArrChan
	go startNamespaceSends(evtChan, 300)

	// Call the batchEvents in client.go to UT it. Use defaults for batchsizes (for now)
	go batchEvents(ctx, evtArrChan, evtChan, uint32(100), uint32(100), &queueLen)

	// Test DrainChan on evtArrChan by sending full chan
	// This should return back without draining a single event
	DrainChan(evtArrChan)

	_, ok := <-evtArrChan
	if !ok {
		t.Error("The evtArrChan should not be empty yet")
		t.Fail()
	}

	// Drain using the receive chan (cast it to a receive-only chan)
	DrainChan((<-chan sdc_internal.ArrayCongroupUpdateEvent)(evtArrChan))
	
	// Now check again
	_, ok = <-evtArrChan
	if ok {
		t.Error("The evtArrChan should be empty by now.")
		t.Fail()
	}
}

func startNamespaceSends(
	evtc chan<- draiosproto.CongroupUpdateEvent,
	numNamespaces int) {

	for i := 0; i < numNamespaces; i++ {
		evtc <- draiosproto.CongroupUpdateEvent {
			Type: draiosproto.CongroupEventType_ADDED.Enum(),
			Object: &draiosproto.ContainerGroup{
				Uid: &draiosproto.CongroupUid{
					Kind:proto.String("k8s_namespace"),
					Id:proto.String(strconv.Itoa(i))},
			},
		}
		
	}
	close(evtc)
}
