package kubecollect

import (
	"cointerface/kubecollect_common"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	clientgoInformersLib "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	draiosproto "protorepo/agent-be/proto"
)

var replicaset CoReplicaSet

func deployment_fixture() {
	// Initialize some variables used in kubecollect package
	if kubecollect_common.StartedMap == nil {
		kubecollect_common.StartedMap = make(map[string]bool)
	}

	// Make resource "deployment" ready
	kubecollect_common.StartedMap["deployments"] = true

	// Create a selector cache
	deploySelectorCache = NewSelectorCache()

	// Run the deployment informer with a fake client.
	// This is needed by AddDeploymentParent to work properly
	client := fake.NewSimpleClientset()
	informers := clientgoInformersLib.NewSharedInformerFactory(client, 0)
	deploymentInf = informers.Apps().V1().Deployments().Informer()
	deployment, _ := createDeploymentCopies()
	deployment.Namespace = "OSoleMioStanFronteAMe"
	replicaset, _ = createReplicaSetCopies()

	isController := true

	replicaset.OwnerReferences = append(replicaset.OwnerReferences, metav1.OwnerReference{
		APIVersion:         "",
		Kind:               "Deployment",
		Name:               deployment.GetName(),
		UID:                deployment.GetUID(),
		Controller:         &isController,
		BlockOwnerDeletion: nil,
	})

	deploymentInf.GetStore().Add(deployment.Deployment)
}

// Creates two deployment objects that are DeepEqual
func createDeploymentCopies() (CoDeployment, CoDeployment) {
	var numReplicas int32 = 5
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			UID:  types.UID("MaramaoPercheSeiMorto"),
			Name: "oldDeployment",
			Labels: map[string]string{
				"label_key0": "label_val0",
				"label_key1": "label_val1",
				"label_key2": "label_val2",
			},
			Annotations: map[string]string{
				"annotation_key0": "annotation_val0",
				"annotation_key1": "annotation_val1",
				"annotation_key2": "annotation_val2",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &numReplicas,
			Paused:   true,
		},
		Status: appsv1.DeploymentStatus{
			Replicas:            numReplicas,
			AvailableReplicas:   numReplicas,
			UnavailableReplicas: numReplicas,
			UpdatedReplicas:     numReplicas,
		},
	}

	orig := CoDeployment{Deployment: deploy}
	copy := CoDeployment{Deployment: deploy.DeepCopy()}
	return orig, copy
}

func deploymentEqualsHelper(t *testing.T, old CoDeployment, new CoDeployment, expected bool) {
	sameEntity, sameLinks := deploymentEquals(old, new)
	res := sameEntity && sameLinks
	if (!sameLinks && sameEntity) || (res != expected) {
		t.Logf("deploymentEquals expected %v, got %v", expected, res)
		t.Logf("sameEntity is %v, sameLinks is %v", sameEntity, sameLinks)
		t.Logf("oldDeployment: %#v", old)
		t.Logf("newDeployment: %#v", new)
		t.Fail()
	}
}

func TestDeploymentEqualsUnchanged(t *testing.T) {
	old, new := createDeploymentCopies()

	deploymentEqualsHelper(t, old, new, true)
}

func TestDeploymentEqualsName(t *testing.T) {
	old, new := createDeploymentCopies()
	new.Name = "newDeployment"

	deploymentEqualsHelper(t, old, new, false)
}

func TestDeploymentEqualsSpecReplicas(t *testing.T) {
	old, new := createDeploymentCopies()
	*new.Spec.Replicas = int32(2)

	deploymentEqualsHelper(t, old, new, false)
}

func TestDeploymentEqualsSpecReplicasNil(t *testing.T) {
	old, new := createDeploymentCopies()
	new.Spec.Replicas = nil

	deploymentEqualsHelper(t, old, new, false)
}

func TestDeploymentEqualsSpecPaused(t *testing.T) {
	old, new := createDeploymentCopies()
	new.Spec.Paused = false

	deploymentEqualsHelper(t, old, new, false)
}

func TestDeploymentEqualsStatusReplicas(t *testing.T) {
	old, new := createDeploymentCopies()
	new.Status.Replicas = 3

	deploymentEqualsHelper(t, old, new, false)
}

func TestDeploymentEqualsStatusAvailableReplicas(t *testing.T) {
	old, new := createDeploymentCopies()
	new.Status.AvailableReplicas = 3

	deploymentEqualsHelper(t, old, new, false)
}
func TestDeploymentEqualsStatusUnavailableReplicas(t *testing.T) {
	old, new := createDeploymentCopies()
	new.Status.UnavailableReplicas = 3

	deploymentEqualsHelper(t, old, new, false)
}
func TestDeploymentEqualsStatusUpdatedReplicas(t *testing.T) {
	old, new := createDeploymentCopies()
	new.Status.UpdatedReplicas = 3

	deploymentEqualsHelper(t, old, new, false)
}

func TestAddDeploymentParents(t *testing.T) {
	var parents []*draiosproto.CongroupUid
	// Owner reference is not null here (See the fixture)
	AddDeploymentParent(&parents, replicaset)

	// Check that the rs parent id is the deployment uid
	if len(parents) != 1 || (*parents[0].Id != string(deploymentInf.GetStore().List()[0].(*appsv1.Deployment).UID)) {
		t.Fail()
	}

	// Test now the old label-selector mechanism
	replicaset.OwnerReferences = nil
	parents = []*draiosproto.CongroupUid{}

	deployment := deploymentInf.GetStore().List()[0].(*appsv1.Deployment)

	replicaset.Namespace = deployment.Namespace

	AddDeploymentParent(&parents, replicaset)

	if len(parents) != 0  {
		t.Fail()
	}
}
