"""Parser tests (FR-1..FR-4)."""

from __future__ import annotations

from iac_threatgen.parsers import parse_iac
from iac_threatgen.parsers.kubernetes import parse_text as k8s_parse
from iac_threatgen.parsers.terraform import parse_text as tf_parse


def test_terraform_resources_and_exposure():
    hcl = """
    resource "aws_s3_bucket" "data" {
      bucket = "x"
      acl    = "public-read"
    }
    resource "aws_security_group" "web" {
      ingress { cidr_blocks = ["0.0.0.0/0"] }
    }
    """
    resources, _ = tf_parse(hcl, "main.tf")
    ids = {r["id"] for r in resources}
    assert ids == {"aws_s3_bucket.data", "aws_security_group.web"}
    assert all(r["exposure"] == "public" for r in resources)
    assert all(r["provider"] == "terraform" for r in resources)


def test_terraform_reference_edges():
    hcl = """
    resource "aws_security_group" "web" { name = "w" }
    resource "aws_instance" "app" {
      vpc_security_group_ids = [aws_security_group.web.id]
    }
    """
    _, edges = tf_parse(hcl, "main.tf")
    assert {"from": "aws_instance.app", "to": "aws_security_group.web", "relation": "references"} in edges


def test_kubernetes_privileged_and_service_edge():
    yaml_text = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  labels: {app: api}
spec:
  template:
    metadata: {labels: {app: api}}
    spec:
      hostNetwork: true
      containers:
        - name: c
          image: img
          securityContext: {privileged: true}
---
apiVersion: v1
kind: Service
metadata: {name: svc}
spec:
  type: LoadBalancer
  selector: {app: api}
"""
    resources, edges = k8s_parse(yaml_text, "k8s.yaml")
    by_id = {r["id"]: r for r in resources}
    dep = by_id["apps/v1/Deployment/api"]
    assert dep["attributes"]["privileged"] is True
    assert dep["attributes"]["hostNetwork"] is True
    svc = by_id["v1/Service/svc"]
    assert svc["exposure"] == "public"
    assert {"from": "v1/Service/svc", "to": "apps/v1/Deployment/api", "relation": "exposes"} in edges


def test_parse_iac_mixed_and_schema_shape(sample_stack):
    g = parse_iac(sample_stack)
    assert g["schema_version"] == "1.0"
    assert g["source"]["type"] == "mixed"
    assert len(g["resources"]) == 6


def test_graceful_degradation(tmp_path):
    (tmp_path / "good.tf").write_text('resource "aws_s3_bucket" "ok" { bucket = "x" }\n')
    (tmp_path / "bad.tf").write_text('resource "aws_s3_bucket" "bad" {\n  bucket = \n')
    g = parse_iac(str(tmp_path))
    assert [r["id"] for r in g["resources"]] == ["aws_s3_bucket.ok"]
    assert len(g["source"]["skipped"]) == 1
    assert "bad.tf" in g["source"]["skipped"][0]["path"]
