from labctl.machine import machine_record

REQUIRED = {
    "cpu_count", "cpu_model", "mem_total_bytes", "kernel", "docker", "containerlab",
    "frr_image", "go", "python", "git_commit", "git_tree_clean",
}


def test_machine_record_has_every_required_field():
    rec = machine_record()
    assert rec["record"] == "machine"
    assert REQUIRED <= rec.keys()
    assert rec["frr_image"].startswith("quay.io/frrouting/frr:")
