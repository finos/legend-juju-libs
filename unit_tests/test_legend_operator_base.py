# Copyright 2021 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module defining tests for the core operator charm library."""

import unittest
from unittest import mock

import jks
import yaml
from charms.finos_legend_libs.v0 import legend_operator_base, legend_operator_testing
from OpenSSL import crypto
from ops import testing as ops_testing


def generate_dummy_cert():
    """Generates a random dummy cert."""
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 4096)
    # create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "us"
    cert.get_subject().ST = "state"
    cert.get_subject().L = "locality"
    cert.get_subject().OU = "org unit"
    cert.get_subject().CN = "common name"
    cert.get_subject().emailAddress = "email"
    cert.set_serial_number(0)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, "sha512")
    return cert


class UtilsTestCase(unittest.TestCase):
    """TestCase covering the various utility methods in the library."""

    def test_add_file_to_container(self):
        """Tests `legend_operator_base.add_file_to_container()`."""
        file_path = "/test/path"
        file_data = "Some file data."

        # Positive test:
        container = mock.MagicMock()
        self.assertTrue(
            legend_operator_base.add_file_to_container(
                container, file_path, file_data, make_dirs=True, raise_on_error=False
            )
        )
        container.push.assert_called_with(file_path, file_data, make_dirs=True)

        # Check make_dir passed:
        container = mock.MagicMock()
        make_dirs = "random value"
        self.assertTrue(
            legend_operator_base.add_file_to_container(
                container, file_path, file_data, make_dirs=make_dirs, raise_on_error=False
            )
        )
        container.push.assert_called_with(file_path, file_data, make_dirs=make_dirs)

        # No re-raise:
        container = mock.MagicMock()
        container.push.side_effect = ValueError
        self.assertFalse(
            legend_operator_base.add_file_to_container(
                container, file_path, file_data, make_dirs=True, raise_on_error=False
            )
        )
        container.push.assert_called_with(file_path, file_data, make_dirs=True)

        # Raises:
        with self.assertRaises(ValueError):
            container = mock.MagicMock()
            container.push.side_effect = ValueError
            legend_operator_base.add_file_to_container(
                container, file_path, file_data, make_dirs=True, raise_on_error=True
            )

    @mock.patch("base64.b64decode")
    @mock.patch("OpenSSL.crypto.load_certificate")
    def test_parse_base64_certificate_formats(self, _load_cert_mock, _b64decode_mock):
        """Tests `legend_operator_base.parse_base64_certificate()`."""
        test_decoded = "test"
        _b64decode_mock.return_value = test_decoded
        test_cert = "some test cert"

        # This shold ensure iterating over all supported formats
        supported_formats = {crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1}

        def _parse_cert(fmt, crt):
            supported_formats.remove(fmt)
            if supported_formats:
                raise ValueError()
            return test_cert

        _load_cert_mock.side_effect = _parse_cert
        cert = legend_operator_base.parse_base64_certificate(test_cert)
        self.assertEqual(cert, test_cert)
        _b64decode_mock.assert_called_with(test_cert)
        _load_cert_mock.assert_has_calls(
            [
                mock.call(crypto.FILETYPE_PEM, test_decoded),
                mock.call(crypto.FILETYPE_ASN1, test_decoded),
            ]
        )

    @mock.patch("OpenSSL.crypto.dump_certificate")
    def test_create_jks_truststore_with_certificates(self, _mock_dump_cert):
        """Tests `legend_operator_base.create_jks_truststore_with_certificates()`."""
        # Bad inputs:
        with self.assertRaises(ValueError):
            legend_operator_base.create_jks_truststore_with_certificates(13)
        with self.assertRaises(ValueError):
            legend_operator_base.create_jks_truststore_with_certificates({"cert": 13})

        # No inputs:
        cert_name = "cert"
        cert_data = "anything"
        _mock_dump_cert.return_value = cert_data
        dummy_cert = generate_dummy_cert()
        store = legend_operator_base.create_jks_truststore_with_certificates(
            {cert_name: dummy_cert}
        )
        _mock_dump_cert.assert_called_once_with(crypto.FILETYPE_ASN1, dummy_cert)
        self.assertIsInstance(store, jks.KeyStore)
        self.assertEqual(store.store_type, legend_operator_base.TRUSTSTORE_TYPE_JKS)
        self.assertTrue(store.certs)
        self.assertTrue(cert_name in store.certs)
        self.assertEqual(store.certs[cert_name].cert, cert_data)

    @mock.patch("subprocess.check_output")
    def test_get_ip_address(self, _mock_check_output):
        """Tests `legend_operator_base.get_ip_address()`."""
        ip = b"random IP"
        _mock_check_output.return_value = ip
        res = legend_operator_base.get_ip_address()
        _mock_check_output.assert_called_once_with(["unit-get", "private-address"])
        self.assertEqual(res, ip.decode())


class TestBaseFinosLegendCharm(legend_operator_testing.BaseFinosLegendCharmTestCase):
    """Baseline testcase testing the `legend_operator_testing.BaseFinosLegendTestCharm` class."""

    @classmethod
    def _set_up_harness(cls):
        rel_data = {
            rel: {"interface": "%s-interfaces" % rel}
            for rel in legend_operator_testing.BaseFinosLegendTestCharm._get_required_relations()
        }
        charm_meta = {
            "name": "legend-base-test",
            "requires": {"ingress": {"interface": "ingress"}},
            "provides": rel_data,
            "containers": {
                legend_operator_testing.BaseFinosLegendTestCharm._get_workload_container_name(): {
                    "resource": "image"
                }
            },
            "resources": {"image": {"type": "oci-image"}},
        }
        config = {
            "options": {
                "external-hostname": {
                    "type": "string",
                    "default": "",
                },
                "log-level-option": {"type": "string"},
            },
        }
        harness = ops_testing.Harness(
            legend_operator_testing.BaseFinosLegendTestCharm,
            meta=yaml.dump(charm_meta),
            config=yaml.dump(config),
        )
        return harness

    def test_workload_container(self):
        """Tests `legend_operator_base.BaseFinosLegendCharm._workload_container`."""
        self._test_workload_container()

    def test_get_logging_level_from_config(self):
        """Tests `legend_operator_base.BaseFinosLegendCharm._get_logging_level_from_config`."""
        self._test_get_logging_level_from_config()

    def test_setup_jks_truststore(self):
        """Tests `legend_operator_base.BaseFinosLegendCharm._setup_jks_truststore`."""
        self._test_setup_jks_truststore()

    @mock.patch("ops.testing._TestingPebbleClient.stop_services")
    def test_get_relation(self, _stop_legend_services):
        """Tests `legend_operator_base.BaseFinosLegendCharm._get_relation`."""
        self._test_get_relation()

    def test_relations_waiting(self):
        """Tests the whole lifecycle of `legend_operator_base.BaseFinosLegendCharm`."""
        self._test_relations_waiting()


class TestBaseFinosCoreServiceLegendCharm(
    legend_operator_testing.TestBaseFinosCoreServiceLegendCharm
):
    """Simulates a core service run."""

    @classmethod
    def _set_up_harness(cls):
        cls = legend_operator_testing.BaseFinosLegendCoreServiceTestCharm
        rel_data = {
            rel: {"interface": "%s-interfaces" % rel} for rel in cls._get_required_relations()
        }
        charm_meta = {
            "name": "legend-base-test",
            "requires": {"ingress": {"interface": "ingress"}},
            "provides": rel_data,
            "containers": {cls._get_workload_container_name(): {"resource": "image"}},
            "resources": {"image": {"type": "oci-image"}},
        }
        charm_config = {
            "options": {
                "external-hostname": {
                    "type": "string",
                    "default": "",
                },
            },
        }
        harness = ops_testing.Harness(
            cls, meta=yaml.dump(charm_meta), config=yaml.dump(charm_config)
        )
        return harness

    def test_get_core_legend_service_configs(self):
        """Tests `BaseFinosLegendCoreServiceCharm._get_core_legend_service_configs`."""
        self._test_get_core_legend_service_configs()

    def test_relations_waiting(self):
        """Tests the whole lifecycle of `legend_operator_base.BaseFinosLegendCoreServiceCharm`."""
        self._test_relations_waiting()

    def test_update_config_gitlab_relation(self):
        """Tests Update config handle of `legend_operator_base.BaseFinosLegendCoreServiceCharm`."""
        self._test_update_config_gitlab_relation()

    def test_upgrade_charm(self):
        """Tests Upgrade handle of `legend_operator_base.BaseFinosLegendCoreServiceCharm`.

        This test will ensure that the Callback URIs are being updated.
        """
        self._test_upgrade_charm()
