package kubecollect

import (
	"testing"
	"time"
	"math/rand"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	resourceOrder := getResourceTypes(resourceList)

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

	resourceOrderNew := getResourceTypes(resourceList)
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

	resourceOrderWithOutCronjobs := getResourceTypes(resourceList)
	
	// Since group version by default is
	// v1ForTesting, no cronjobs should be added
	checkNoCronjobsExistHelper(t, resourceOrderWithOutCronjobs, true)

	// Now modify groupversion to the supported value and check cronjobs exist
	resourceList[0].GroupVersion = "batch/v2alpha1"
	
	resourceOrderWithCronjobs := getResourceTypes(resourceList)
	checkNoCronjobsExistHelper(t,resourceOrderWithCronjobs, false)
}
