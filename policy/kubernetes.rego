# Conftest rules for Kubernetes manifests (Deployments, Pods, StatefulSets, DaemonSets, Jobs).
package kubernetes

import rego.v1

pod_spec := input.spec.template.spec if input.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
pod_spec := input.spec if input.kind == "Pod"
pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

containers contains c if some c in pod_spec.containers
containers contains c if some c in pod_spec.initContainers

name := sprintf("%s/%s", [input.kind, input.metadata.name])

deny contains r if {
	some c in containers
	c.securityContext.privileged == true
	r := {"msg": sprintf("%s: container %q is privileged", [name, c.name]), "id": "K8S001",
		"title": "Privileged container", "severity": "critical", "cwe": "250"}
}

deny contains r if {
	some c in containers
	not c.securityContext.runAsNonRoot == true
	not pod_spec.securityContext.runAsNonRoot == true
	r := {"msg": sprintf("%s: container %q may run as root (runAsNonRoot is not set)", [name, c.name]),
		"id": "K8S002", "title": "Container may run as root", "severity": "medium", "cwe": "250"}
}

deny contains r if {
	some c in containers
	not c.securityContext.allowPrivilegeEscalation == false
	r := {"msg": sprintf("%s: container %q allows privilege escalation", [name, c.name]),
		"id": "K8S003", "title": "Privilege escalation allowed", "severity": "medium", "cwe": "269"}
}

deny contains r if {
	some c in containers
	not c.resources.limits.memory
	r := {"msg": sprintf("%s: container %q has no memory limit", [name, c.name]),
		"id": "K8S004", "title": "No memory limit", "severity": "low", "cwe": "400"}
}

deny contains r if {
	some field in ["hostNetwork", "hostPID", "hostIPC"]
	pod_spec[field] == true
	r := {"msg": sprintf("%s: shares the host's %s", [name, field]),
		"id": "K8S005", "title": "Shares host namespaces", "severity": "high", "cwe": "668"}
}
