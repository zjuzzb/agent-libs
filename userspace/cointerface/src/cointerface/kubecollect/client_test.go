package kubecollect

import (
	"testing"
	"fmt"
	//"k8s.io/api/core/v1"
	v1meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func createAPIResourceList() (resourceList *v1meta.APIResourceList) {

	orig:= &v1meta.APIResourceList {
		GroupVersion: "v1ForTesting",
		APIResources: []v1meta.APIResource{
			v1meta.APIResource{
				Name: "pods",
			},
			v1meta.APIResource{
				Name: "namespaces",
			},
		},
	}

	return orig
}

func resourceOrderingHelper(t *testing.T , resourceList []*v1meta.APIResourceList) {

	
	resourceOrder := getResourceTypes(resourceList)
	for _, str := range resourceOrder {
		fmt.Println(str)
	}
	
	if( resourceOrder[0] != "namespaces") {
		t.Error("Namespaces isn't first on the list")
		t.Fail()
	}
	
}

func TestBasicResourceOrdering(t *testing.T) {

	resourceList := []*v1meta.APIResourceList{ createAPIResourceList(),
		createAPIResourceList()}

	resourceOrderingHelper(t,resourceList);
}
