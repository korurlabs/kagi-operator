/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// A managed Secret may only be written or deleted by the one KagiSecret or
// KagiCertificate that created it. Without that rule, a resource whose
// spec.managedSecret names an existing Secret (a TLS Secret, a registry
// credential, the operator's own token Secret) would overwrite it, and deleting
// that resource would delete it, because the operator holds cluster-wide write
// and delete rights on Secrets.
//
// Ownership is the managed-by label plus the annotationOwner annotation. It
// cannot be an ownerReference: an ownerReference carries no namespace, so the
// owner must live in the Secret's own namespace, while these resources usually
// live in the operator's namespace and write their Secret into the
// application's. With the owner elsewhere, the garbage collector finds no owner
// in the Secret's namespace and deletes the Secret.
const (
	// annotationOwner names the resource that owns a managed Secret, as
	// <Kind>/<namespace>/<name>. It holds the name and not the UID because
	// GitOps deletes and re-creates these resources: the re-created resource
	// gets a new UID and must still own the Secret it wrote before.
	annotationOwner = "kagi.pw/owner"

	kindKagiSecret      = "KagiSecret"
	kindKagiCertificate = "KagiCertificate"

	// reasonSecretOwnedByOther is the Ready reason when the managed Secret
	// belongs to another KagiSecret or KagiCertificate.
	reasonSecretOwnedByOther = "SecretOwnedByOther"

	// reasonSecretNotManaged is the Ready reason when the managed Secret exists
	// but the operator did not create it.
	reasonSecretNotManaged = "SecretNotManaged"

	// reasonSecretReconcileFailed is the Ready reason for any other failure to
	// read or write the managed Secret.
	reasonSecretReconcileFailed = "SecretReconcileFailed"

	// reasonCrossNamespaceReferenceDenied is the Ready reason when a resource
	// outside the operator's namespace names a Secret in another namespace.
	reasonCrossNamespaceReferenceDenied = "CrossNamespaceReferenceDenied"

	// reasonInvalidSpec is the Ready reason for a spec the operator refuses to
	// act on.
	reasonInvalidSpec = "InvalidSpec"

	// eventReasonSecretLeftInPlace is the reason of the Warning Event emitted
	// when a deleted resource leaves its managed Secret in place because it
	// does not own it.
	eventReasonSecretLeftInPlace = "SecretLeftInPlace"

	// eventReasonSecretCleanupFailed is the reason of the Warning Event emitted
	// when a deleted resource could not delete the managed Secret it owns.
	eventReasonSecretCleanupFailed = "SecretCleanupFailed"
)

// secretOwnership is how an existing Secret relates to the resource that names
// it in spec.managedSecret.
type secretOwnership int

const (
	// secretOwned: the Secret carries the managed-by label and names this
	// resource in annotationOwner.
	secretOwned secretOwnership = iota

	// secretUnclaimed: the Secret carries the managed-by label and the
	// data-hash annotation but no owner. Operator releases before
	// annotationOwner wrote every KagiSecret and KagiCertificate Secret this
	// way, so a resource may adopt it; adoptionRefusal says which one. The
	// data-hash annotation is what sets such a Secret apart from other Secrets
	// the operator labels, above all its own webhook serving certificate,
	// which carries the label alone and must never be adopted.
	secretUnclaimed

	// secretOwnedByOther: the Secret names another resource in annotationOwner.
	secretOwnedByOther

	// secretNotManaged: the operator did not create the Secret for a
	// KagiSecret or KagiCertificate. It lacks the managed-by label, or it has
	// the label without an owner or a data hash.
	secretNotManaged
)

// managedSecretOwner returns the annotationOwner value for a resource.
func managedSecretOwner(kind string, obj client.Object) string {
	return kind + "/" + obj.GetNamespace() + "/" + obj.GetName()
}

// managedSecretClaim is what a KagiSecret or KagiCertificate asserts about the
// Secret its spec.managedSecret names.
type managedSecretClaim struct {
	// kind is the resource's kind, kindKagiSecret or kindKagiCertificate.
	kind string

	// owner is the resource's annotationOwner value.
	owner string

	// namespace is the resource's own namespace.
	namespace string

	// operatorNamespace is the namespace the operator runs in, or "" when it
	// is not known.
	operatorNamespace string

	// identity holds the labels that tie a managed Secret to the resource's
	// Kagi binding: the app ID and environment of a KagiSecret, the
	// certificate ID of a KagiCertificate. Every operator release since the
	// kagi.pw label prefix wrote them on every managed Secret, and the
	// operator writes them again on every update. It is nil while the
	// resource has not resolved its binding, and then nothing proves that an
	// unclaimed Secret was written for it.
	identity map[string]string
}

// labels returns the labels the operator writes on the claimed Secret.
func (c *managedSecretClaim) labels() map[string]string {
	labels := maps.Clone(c.identity)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[labelManagedBy] = managedByValue
	return labels
}

// classifySecretOwnership reports how secret relates to owner.
func classifySecretOwnership(secret *corev1.Secret, owner string) secretOwnership {
	if secret.Labels[labelManagedBy] != managedByValue {
		return secretNotManaged
	}
	switch secret.Annotations[annotationOwner] {
	case owner:
		return secretOwned
	case "":
		if secret.Annotations[annotationHash] == "" {
			return secretNotManaged
		}
		return secretUnclaimed
	default:
		return secretOwnedByOther
	}
}

// adoptionRefusal returns why claim may not adopt the unclaimed Secret secret,
// or "" when it may. Deletion applies the same test before it deletes an
// unclaimed Secret, because deleting a Secret needs the same proof as taking
// it over.
//
// An unclaimed Secret only proves that an earlier release wrote it for some
// KagiSecret or KagiCertificate, not for which one, and the first resource to
// write to it adopts it, with the right to overwrite and delete it. The
// identity labels do not settle the question: they come from specs that are
// often public in Git, so anyone can copy them. What settles it is where the
// adopter lives, judged against where the resource that wrote the Secret lives:
//
//   - A KagiSecret adopts only from the operator's namespace. KagiSecrets
//     belong there and deliver into the application namespaces, and only
//     cluster admins should create resources there. A KagiSecret created next to the
//     Secret could otherwise take it over before its real owner writes again.
//   - A KagiCertificate also adopts from the Secret's own namespace, because
//     certificates write their Secret into their own namespace.
//   - With the operator's namespace unknown, checkSecretReferences holds every
//     resource to its own namespace, so only a resource in the Secret's
//     namespace can have written it, and only such a resource adopts it.
//
// The Secret must also carry the identity labels the earlier release wrote
// for the resource's Kagi binding.
//
// Adoption keeps the Secret's ownerReferences and finalizers, because the
// update replaces only labels, annotations, data and type. A Secret that has
// them, or that is immutable, was changed by someone other than the operator
// and is refused, so foreign garbage-collection or deletion hooks never end up
// on a Secret the operator then calls its own.
func adoptionRefusal(secret *corev1.Secret, claim *managedSecretClaim) string {
	if why := adoptionNamespaceRefusal(secret, claim); why != "" {
		return why
	}
	if len(claim.identity) == 0 {
		return "this resource has not resolved its Kagi binding, so nothing shows the Secret was written for it"
	}
	for _, key := range slices.Sorted(maps.Keys(claim.identity)) {
		if got, want := secret.Labels[key], claim.identity[key]; got != want {
			return fmt.Sprintf("its label %s is %q, but this resource needs %q", key, got, want)
		}
	}
	switch {
	case len(secret.OwnerReferences) > 0:
		return "it has ownerReferences, which the operator never sets"
	case len(secret.Finalizers) > 0:
		return "it has finalizers, which the operator never sets"
	case secret.Immutable != nil && *secret.Immutable:
		return "it is immutable, which the operator never sets"
	}
	return ""
}

// adoptionNamespaceRefusal returns why claim may not adopt the unclaimed
// Secret secret from its namespace, or "" when it may; see adoptionRefusal.
func adoptionNamespaceRefusal(secret *corev1.Secret, claim *managedSecretClaim) string {
	inOwnNamespace := claim.namespace == secret.Namespace
	switch {
	case claim.operatorNamespace == "":
		if inOwnNamespace {
			return ""
		}
		return fmt.Sprintf("the operator's namespace is unknown, because POD_NAMESPACE is not set, "+
			"so only a resource in namespace %s may take it over", secret.Namespace)
	case claim.namespace == claim.operatorNamespace:
		return ""
	case claim.kind == kindKagiCertificate:
		if inOwnNamespace {
			return ""
		}
		return fmt.Sprintf("only a KagiCertificate in namespace %s or a resource in the operator's namespace %s may take it over",
			secret.Namespace, claim.operatorNamespace)
	default:
		return fmt.Sprintf("only a resource in the operator's namespace %s may take over a Secret an earlier release wrote "+
			"for a KagiSecret", claim.operatorNamespace)
	}
}

// secretRefusal refuses to act on a Secret a resource names. reason is the
// Ready condition reason the reconcilers report.
type secretRefusal struct {
	reason  string
	message string
}

func (e *secretRefusal) Error() string {
	return e.message
}

// checkSecretWritable returns nil when claim may write secret: the claiming
// resource owns the Secret, or the Secret is unclaimed and the resource may
// adopt it on the write. Any other Secret yields a *secretRefusal that names
// the Secret and, when there is one, its owner.
func checkSecretWritable(secret *corev1.Secret, claim *managedSecretClaim) error {
	switch classifySecretOwnership(secret, claim.owner) {
	case secretOwned:
		return nil
	case secretUnclaimed:
		why := adoptionRefusal(secret, claim)
		if why == "" {
			return nil
		}
		return &secretRefusal{
			reason: reasonSecretNotManaged,
			message: fmt.Sprintf(
				"Secret %s/%s was written by an earlier operator release and has no owner, but %s may not take it over: %s; "+
					"the operator will not write to it. Point spec.managedSecret at a Secret name that does not exist yet, "+
					"or delete the Secret so the operator creates it again",
				secret.Namespace, secret.Name, claim.owner, why),
		}
	case secretOwnedByOther:
		recorded := secret.Annotations[annotationOwner]
		return &secretRefusal{
			reason: reasonSecretOwnedByOther,
			message: fmt.Sprintf(
				"Secret %s/%s is owned by %s, not by %s; the operator will not write to it. "+
					"Point spec.managedSecret at another Secret name, or delete %s first",
				secret.Namespace, secret.Name, recorded, claim.owner, recorded),
		}
	default:
		return &secretRefusal{
			reason: reasonSecretNotManaged,
			message: fmt.Sprintf(
				"Secret %s/%s exists and was not created by the Kagi operator for a KagiSecret or KagiCertificate; "+
					"the operator will not write to it. Point spec.managedSecret at a Secret name that does not exist yet",
				secret.Namespace, secret.Name),
		}
	}
}

// managedSecretFailureReason returns the Ready reason for an error from
// checkSecretReferences, guardManagedSecret or writeManagedSecret.
func managedSecretFailureReason(err error) string {
	var refusal *secretRefusal
	if errors.As(err, &refusal) {
		return refusal.reason
	}
	return reasonSecretReconcileFailed
}

// secretReference is a Secret namespace that a resource's spec names.
type secretReference struct {
	// field is the spec field that holds the namespace.
	field string

	// namespace is the value of field; "" means the resource's own namespace.
	namespace string
}

// checkSecretReferences returns a *secretRefusal with reason
// reasonCrossNamespaceReferenceDenied when resource, which is not in the
// operator's namespace, names a Secret in another namespace.
//
// The operator reads and writes Secrets in every namespace. Without this rule
// anyone who may create a KagiSecret or KagiCertificate in their own namespace
// borrows those rights: a spec.tokenSecret in another namespace makes the
// operator read someone else's Kagi token and act with it, and a
// spec.managedSecret in another namespace makes it write Kagi secret values or
// a private key there, and roll out Deployments there. The operator's
// namespace keeps cross-namespace references: it holds the operator's own
// token, only cluster admins should create resources there, and its resources
// deliver Secrets into the application namespaces. With operatorNamespace
// unknown, every resource is held to its own namespace.
func checkSecretReferences(resource client.Object, kind, operatorNamespace string, refs ...secretReference) error {
	own := resource.GetNamespace()
	if operatorNamespace != "" && own == operatorNamespace {
		return nil
	}
	operatorNamespaceName := operatorNamespace
	if operatorNamespaceName == "" {
		operatorNamespaceName = "unknown, because POD_NAMESPACE is not set"
	}
	for _, ref := range refs {
		if ref.namespace == "" || ref.namespace == own {
			continue
		}
		return &secretRefusal{
			reason: reasonCrossNamespaceReferenceDenied,
			message: fmt.Sprintf(
				"%s is %q, but a %s outside the operator's namespace (%s) may only name Secrets in its own namespace %q; "+
					"the operator reads and writes no Secret for it. Set %s to %q, or ask a cluster admin to create the %s "+
					"in the operator's namespace",
				ref.field, ref.namespace, kind, operatorNamespaceName, own, ref.field, own, kind),
		}
	}
	return nil
}

// checkManagedSecretType returns a *secretRefusal with reason
// reasonInvalidSpec when secretType is not a type the operator writes.
//
// A KagiSecret writes Opaque Secrets. Its keys are whatever names the Kagi
// secrets carry, and a key such as tls.crt does not make that set a TLS
// Secret: a typed kind promises the cluster a complete, well-formed set of
// keys, which an arbitrary selection of secrets cannot keep, while Opaque
// promises nothing. A KagiCertificate writes kubernetes.io/tls, to which it maps
// an empty type and Opaque. Every other type is refused, because some types
// mean more to the cluster than the data they hold: the token controller fills
// a kubernetes.io/service-account-token Secret with a ServiceAccount token. The
// CRD enforces the same list at admission, but a resource stored before that
// CRD was applied, or an operator that runs ahead of its CRD upgrade, is only
// caught here.
func checkManagedSecretType(secretType string) error {
	switch corev1.SecretType(secretType) {
	case "", corev1.SecretTypeOpaque, corev1.SecretTypeTLS:
		return nil
	}
	return &secretRefusal{
		reason: reasonInvalidSpec,
		message: fmt.Sprintf("spec.managedSecret.type %q is not supported; the operator only writes Secrets of type %s or %s",
			secretType, corev1.SecretTypeOpaque, corev1.SecretTypeTLS),
	}
}

// guardManagedSecret returns nil when claim may write the Secret at key, which
// includes a Secret that does not exist yet. The reconcilers call it before
// they fetch secret values or a certificate. Token resolution, app or
// certificate ID resolution and the KagiSecret version probe still run before
// it, but none of them returns secret material, so a resource that points at a
// Secret it may not write never pulls secret values or a private key into the
// operator. writeManagedSecret checks again at write time; this check only
// saves the fetch.
func guardManagedSecret(ctx context.Context, c client.Reader, key types.NamespacedName, claim *managedSecretClaim) error {
	var existing corev1.Secret
	if err := c.Get(ctx, key, &existing); err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to read managed Secret %s: %w", key, err)
	}
	return checkSecretWritable(&existing, claim)
}

// desiredManagedSecret is the state a reconciler wants its managed Secret in.
type desiredManagedSecret struct {
	key        types.NamespacedName
	claim      *managedSecretClaim
	dataHash   string
	data       map[string][]byte
	secretType corev1.SecretType
}

// annotations returns the annotations the operator writes on a managed Secret.
func (d *desiredManagedSecret) annotations() map[string]string {
	return map[string]string{
		annotationHash:  d.dataHash,
		annotationOwner: d.claim.owner,
	}
}

// writeManagedSecret creates the managed Secret, or updates it when the
// resource owns it or adopts it. It returns true when it wrote. A Secret that
// belongs to another resource, that the operator did not create, or that the
// resource may not adopt, is left untouched and yields a *secretRefusal.
//
// The update carries the resourceVersion of the Secret that was classified, so
// a Secret changed in between fails the update instead of being overwritten.
// A Secret created in between fails the create with AlreadyExists, and the
// retry classifies it.
func writeManagedSecret(ctx context.Context, c client.Client, desired *desiredManagedSecret) (bool, error) {
	labels := desired.claim.labels()
	var existing corev1.Secret
	if err := c.Get(ctx, desired.key, &existing); err != nil {
		if !apierrors.IsNotFound(err) {
			return false, err
		}
		created := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        desired.key.Name,
				Namespace:   desired.key.Namespace,
				Labels:      labels,
				Annotations: desired.annotations(),
			},
			Type: desired.secretType,
			Data: desired.data,
		}
		if err := c.Create(ctx, created); err != nil {
			return false, err
		}
		return true, nil
	}

	if err := checkSecretWritable(&existing, desired.claim); err != nil {
		return false, err
	}
	adopting := classifySecretOwnership(&existing, desired.claim.owner) == secretUnclaimed

	// Fast path: data unchanged and metadata already matches, so a resync that
	// sees the same upstream data does not write at all. An unclaimed Secret
	// never takes it, because adopting it means stamping the owner.
	if !adopting && existing.Annotations[annotationHash] == desired.dataHash &&
		equality.Semantic.DeepEqual(existing.Labels, labels) &&
		equality.Semantic.DeepEqual(existing.Data, desired.data) &&
		existing.Type == desired.secretType {
		return false, nil
	}

	existing.Labels = labels
	existing.Annotations = desired.annotations()
	existing.Data = desired.data
	existing.Type = desired.secretType
	if err := c.Update(ctx, &existing); err != nil {
		return false, err
	}
	if adopting {
		logf.FromContext(ctx).Info("Adopted managed Secret that had no owner annotation",
			"secret", desired.key.String(), "owner", desired.claim.owner)
	}
	return true, nil
}

// liveReader returns apiReader when it is set and c otherwise. The reconcilers
// pass the manager's API reader, which reads from the API server rather than
// the informer cache.
func liveReader(apiReader client.Reader, c client.Client) client.Reader {
	if apiReader != nil {
		return apiReader
	}
	return c
}

// managedSecretRelease is what the deletion of a resource needs to release its
// managed Secret.
type managedSecretRelease struct {
	// reader should read from the API server; see deleteManagedSecret.
	reader client.Reader
	writer client.Writer

	// recorder emits the Warning Events. It may be nil, as in tests that do
	// not check Events; every Event repeats a log line or a returned error.
	recorder record.EventRecorder

	operatorNamespace string
}

// release deletes the managed Secret at key during the deletion of resource,
// when resource may reference it and either owns it or could adopt it; claim
// is what resource claims about the Secret, with the identity its status
// recorded. It returns nil when the
// finalizer may go: the Secret was deleted or was already gone, or it was
// deliberately left in place, which a Warning Event on resource reports.
//
// Any other failure is returned, after a Warning Event, and the caller keeps
// its finalizer so that the rate limiter retries. Removing the finalizer
// anyway would orphan a Secret that holds secret values or a private key and
// that no resource manages any more.
func (rel *managedSecretRelease) release(
	ctx context.Context, resource client.Object, claim *managedSecretClaim, key types.NamespacedName, ref secretReference,
) error {
	if err := checkSecretReferences(resource, claim.kind, rel.operatorNamespace, ref); err != nil {
		logf.FromContext(ctx).Info("Left Secret in place on deletion because the resource may not reference it",
			"secret", key.String(), "reason", err.Error())
		rel.warn(resource, eventReasonSecretLeftInPlace, "Left Secret %s in place on deletion: %v", key, err)
		return nil
	}
	kept, err := deleteManagedSecret(ctx, rel.reader, rel.writer, key, claim)
	if err != nil {
		rel.warn(resource, eventReasonSecretCleanupFailed,
			"Could not delete managed Secret %s; the finalizer stays and the deletion is retried: %v", key, err)
		return fmt.Errorf("failed to clean up managed Secret %s; the finalizer stays until it succeeds: %w", key, err)
	}
	if kept != "" {
		rel.warn(resource, eventReasonSecretLeftInPlace, "%s", kept)
	}
	return nil
}

// warn emits a Warning Event on obj when a recorder is set.
func (rel *managedSecretRelease) warn(obj runtime.Object, reason, messageFmt string, args ...any) {
	if rel.recorder == nil {
		return
	}
	rel.recorder.Eventf(obj, corev1.EventTypeWarning, reason, messageFmt, args...)
}

// deleteManagedSecret deletes the managed Secret at key during deletion of the
// resource that makes claim, but only when that resource owns it, or when the
// Secret is unclaimed and adoptionRefusal would let the resource adopt it. An
// unclaimed Secret the resource could have adopted is deleted too, because an
// earlier release wrote it for this resource and leaving it would leave
// secret values or a private key that nothing manages any more. Any other
// Secret is left in place and logged, and the returned message says why, so
// deleting a resource never deletes a Secret it did not create and never gets
// stuck on one. The message is empty when the Secret was deleted or did not
// exist.
//
// The delete is conditional on the UID and resourceVersion that were checked,
// so a Secret replaced or relabelled in between is not deleted. When that
// precondition fails, the Secret is read and checked once more: an owned
// Secret that was only updated in between is still deleted, and one that
// changed hands is left alone. reader should read from the API server, because
// a cache that has not seen the change yet returns the same stale Secret and
// the second delete fails the same way.
func deleteManagedSecret(
	ctx context.Context, reader client.Reader, writer client.Writer, key types.NamespacedName, claim *managedSecretClaim,
) (string, error) {
	const attempts = 2
	var err error
	for range attempts {
		var kept string
		kept, err = deleteManagedSecretIfOwned(ctx, reader, writer, key, claim)
		if !apierrors.IsConflict(err) {
			return kept, err
		}
	}
	return "", fmt.Errorf("managed Secret %s kept changing during deletion; left in place: %w", key, err)
}

// deleteManagedSecretIfOwned makes one attempt of deleteManagedSecret.
func deleteManagedSecretIfOwned(
	ctx context.Context, reader client.Reader, writer client.Writer, key types.NamespacedName, claim *managedSecretClaim,
) (string, error) {
	var existing corev1.Secret
	if err := reader.Get(ctx, key, &existing); err != nil {
		if apierrors.IsNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read managed Secret %s: %w", key, err)
	}

	log := logf.FromContext(ctx)
	ownership := classifySecretOwnership(&existing, claim.owner)
	switch ownership {
	case secretOwned:
	case secretUnclaimed:
		if why := adoptionRefusal(&existing, claim); why != "" {
			log.Info("Left Secret in place on deletion because it has no owner and this resource may not take it over",
				"secret", key.String(), "owner", claim.owner, "reason", why)
			return fmt.Sprintf("Left Secret %s in place on deletion because it has no owner and %s may not take it over: %s",
				key, claim.owner, why), nil
		}
	default:
		managedBy := existing.Labels[labelManagedBy]
		recordedOwner := existing.Annotations[annotationOwner]
		log.Info("Left Secret in place on deletion because this resource does not own it",
			"secret", key.String(), "owner", claim.owner, "managedBy", managedBy, "recordedOwner", recordedOwner)
		return fmt.Sprintf("Left Secret %s in place on deletion because %s does not own it "+
			"(label %s=%q, annotation %s=%q)", key, claim.owner, labelManagedBy, managedBy, annotationOwner, recordedOwner), nil
	}

	uid := existing.UID
	resourceVersion := existing.ResourceVersion
	err := writer.Delete(ctx, &existing, client.Preconditions{UID: &uid, ResourceVersion: &resourceVersion})
	if apierrors.IsNotFound(err) {
		return "", nil
	}
	if err == nil && ownership == secretUnclaimed {
		log.Info("Deleted managed Secret that had no owner annotation", "secret", key.String(), "owner", claim.owner)
	}
	return "", err
}
