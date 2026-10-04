"""Tests for scripts/validate-segmentation.py."""

import copy


def fails(issues, validator):
    return [i for i in issues if i.startswith(validator.FAIL)]


def warns(issues, validator):
    return [i for i in issues if i.startswith(validator.WARN)]


def test_shipped_design_is_clean(validator, capsys):
    assert validator.main() == 0
    out = capsys.readouterr().out
    assert "0 failure(s), 0 warning(s)" in out


class TestVlans:
    def test_duplicate_vlan_id(self, validator, design):
        vlans = design["vlans"] + [dict(design["vlans"][0], vlan_name="Shadow")]
        assert len(fails(validator.check_duplicate_vlans(vlans), validator)) == 1

    def test_subnet_overlap(self, validator, design):
        vlans = design["vlans"] + [dict(design["vlans"][0], vlan_id="11", vlan_name="Overlap", cidr="16")]
        assert fails(validator.check_subnet_overlap(vlans), validator)

    def test_invalid_subnet(self, validator, design):
        vlans = [dict(design["vlans"][0], subnet="10.10.0.300")]
        assert fails(validator.check_subnet_overlap(vlans), validator)


class TestFirewallRules:
    def test_unknown_vlan_reference(self, validator, design):
        rules = [dict(design["rules"][0], rule_id="555", dest_vlan="Pharmacy")]
        issues = validator.check_firewall_vlan_consistency(rules, design["vlans"])
        assert any("unknown destination VLAN 'Pharmacy'" in i for i in issues)

    def test_missing_default_deny(self, validator, design):
        assert warns(validator.check_global_deny_rules(design["rules"][:-1]), validator)

    def test_default_rule_that_allows_is_a_failure(self, validator, design):
        rules = design["rules"][:-1] + [dict(design["rules"][-1], action="Allow")]
        assert fails(validator.check_global_deny_rules(rules), validator)

    def test_no_rules(self, validator):
        assert fails(validator.check_global_deny_rules([]), validator)

    def test_catch_all_any_rules_are_not_intra_vlan(self, validator, design):
        assert validator.check_intra_vlan_rules(design["rules"]) == []

    def test_real_intra_vlan_deny_warns(self, validator, design):
        rule = dict(design["rules"][0], rule_id="560", source_vlan="Guest", dest_vlan="Guest", action="Deny")
        assert len(warns(validator.check_intra_vlan_rules([rule]), validator)) == 1


class TestDeviceInventory:
    def check(self, validator, design, devices):
        return validator.check_device_inventory(devices, design["vlans"], design["addressing"])

    def test_shipped_inventory_is_clean(self, validator, design):
        assert self.check(validator, design, design["devices"]) == []

    def _mutate(self, design, hostname, **changes):
        devices = copy.deepcopy(design["devices"])
        for d in devices:
            if d["hostname"] == hostname:
                d.update(changes)
        return devices

    def test_ip_outside_vlan_subnet(self, validator, design):
        devices = self._mutate(design, "lab-pc-01", ip_address="10.10.0.20")
        assert any("outside VLAN 20" in i for i in self.check(validator, design, devices))

    def test_duplicate_ip(self, validator, design):
        devices = self._mutate(design, "lab-pc-01", ip_address="10.20.0.10")
        assert any("assigned to both" in i for i in self.check(validator, design, devices))

    def test_static_inside_dhcp_pool(self, validator, design):
        devices = self._mutate(design, "lab-pc-01", ip_address="10.20.0.150")
        assert any("DHCP pool" in i for i in self.check(validator, design, devices))

    def test_static_on_gateway_address(self, validator, design):
        devices = self._mutate(design, "lab-pc-01", ip_address="10.20.0.1")
        assert any("gateway address" in i for i in self.check(validator, design, devices))

    def test_phi_device_on_guest_vlan_fails(self, validator, design):
        devices = self._mutate(design, "lab-pc-01", vlan_id="40", ip_address="10.40.0.20")
        issues = self.check(validator, design, devices)
        assert any("PHI-handling device lab-pc-01" in i for i in fails(issues, validator))

    def test_unknown_vlan(self, validator, design):
        devices = self._mutate(design, "lab-pc-01", vlan_id="77")
        assert any("unknown VLAN '77'" in i for i in self.check(validator, design, devices))

    def test_static_count_drift_warns(self, validator, design):
        devices = [d for d in design["devices"] if d["hostname"] != "dmz-dns-01"]
        issues = self.check(validator, design, devices)
        assert any("VLAN 254 plan reserves 3" in i for i in warns(issues, validator))
