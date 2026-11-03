# Conftest rules for Dockerfiles. Conftest has no checks of its own, so these are ours.
# Each rule gives an id, a title, a severity and (where there is one) a CWE number; the portal reads them.
package dockerfile

import rego.v1

# All instructions. Conftest gives a Dockerfile as a list of instructions (or, with several files, a list of lists).
cmds contains c if {
	some c in input
	is_object(c)
}

cmds contains c if {
	some part in input
	is_array(part)
	some c in part
}

is_dockerfile if {
	some c in cmds
	c.Cmd == "from"
}

final_stage := max({c.Stage | some c in cmds})

deny contains r if {
	is_dockerfile
	not any_user
	r := {"msg": "No USER instruction: the container runs as root", "id": "DF001",
		"title": "Container runs as root", "severity": "high", "cwe": "250"}
}

any_user if {
	some c in cmds
	c.Stage == final_stage
	c.Cmd == "user"
}

deny contains r if {
	some c in cmds
	c.Cmd == "from"
	image := c.Value[0]
	image != "scratch"
	not contains(image, "$")
	not lower(image) in stage_names
	untagged(image)
	r := {"msg": sprintf("Base image %q has no fixed version (tag or digest)", [image]), "id": "DF002",
		"title": "Base image without a fixed version", "severity": "medium", "cwe": "1357"}
}

# "FROM node:22 AS build" ... "FROM build": the second FROM names an earlier stage, not an image.
stage_names contains lower(c.Value[2]) if {
	some c in cmds
	c.Cmd == "from"
	count(c.Value) >= 3
}

untagged(image) if endswith(image, ":latest")
untagged(image) if {
	not contains(image, "@")
	parts := split(image, "/")
	not contains(parts[count(parts) - 1], ":")
}

deny contains r if {
	some c in cmds
	c.Cmd == "add"
	some v in c.Value
	regex.match(`^https?://`, v)
	r := {"msg": sprintf("ADD downloads %q without checking it; use curl + checksum", [v]), "id": "DF003",
		"title": "ADD from a URL", "severity": "medium", "cwe": "494"}
}

deny contains r if {
	some c in cmds
	c.Cmd == "run"
	line := concat(" ", c.Value)
	regex.match(`(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z)?sh`, line)
	r := {"msg": "RUN pipes a downloaded script straight into a shell", "id": "DF004",
		"title": "Download piped into shell", "severity": "medium", "cwe": "494"}
}

deny contains r if {
	some c in cmds
	c.Cmd == "run"
	regex.match(`(^|[\s;&|])sudo\s`, concat(" ", c.Value))
	r := {"msg": "RUN uses sudo", "id": "DF005", "title": "sudo inside a Dockerfile", "severity": "low", "cwe": "250"}
}
