package kubecollect

import (
	"testing"

	"k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Creates two deployment objects that are DeepEqual
func createDeploymentCopies() (coDeployment, coDeployment) {
	var numReplicas int32 = 5
	deploy := &v1beta1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "oldDeployment",
			Labels: map[string]string{
				"label_key0":"label_val0",
				"label_key1":"label_val1",
				"label_key2":"label_val2",
			},
			Annotations: map[string]string{
				"annotation_key0":"annotation_val0",
				"annotation_key1":"annotation_val1",
				"annotation_key2":"annotation_val2",
			},
		},
		Spec: v1beta1.DeploymentSpec{
			Replicas: &numReplicas,
			Paused: true,
		},
		Status: v1beta1.DeploymentStatus{
			Replicas: numReplicas,
			AvailableReplicas: numReplicas,
			UnavailableReplicas: numReplicas,
			UpdatedReplicas: numReplicas,
		},
	}

	orig := coDeployment{ Deployment: deploy }
	copy := coDeployment{ Deployment: deploy.DeepCopy() }
	return orig, copy
}

func deploymentEqualsHelper(t *testing.T, old coDeployment, new coDeployment, expected bool) {
	sameEntity, sameLinks := deploymentEquals(old, new)
	res := sameEntity && sameLinks
	if (!sameLinks && sameEntity) || (res != expected)  {
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
