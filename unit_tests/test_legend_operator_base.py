# Copyright 2021 Canonical
# See LICENSE file for licensing details.

"""Module defining tests for the core operator charm library."""

import unittest
from unittest import mock

import jks
import yaml
from ops import testing as ops_testing
from OpenSSL import crypto

from charms.finos_legend_libs.v0 import legend_operator_base
from charms.finos_legend_libs.v0 import legend_operator_testing


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
    cert.sign(k, 'sha512')
    return cert


class UtilsTestCase(unittest.TestCase):
    """TestCase covering the various utility methods in the library."""
    def test_add_file_to_container(self):
        file_path = "/test/path"
        file_data = "Some file data."

        # Positive test:
        container = mock.MagicMock()
        self.assertTrue(
            legend_operator_base.add_file_to_container(
                container, file_path, file_data, make_dirs=True,
                raise_on_error=False))
        container.push.assert_called_with(file_path, file_data, make_dirs=True)

        # Check make_dir passed:
        container = mock.MagicMock()
        make_dirs = "random value"
        self.assertTrue(
            legend_operator_base.add_file_to_container(
                container, file_path, file_data, make_dirs=make_dirs,
                raise_on_error=False))
        container.push.assert_called_with(file_path, file_data, make_dirs=make_dirs)

        # No re-raise:
        container = mock.MagicMock()
        container.push.side_effect = ValueError
        self.assertFalse(
            legend_operator_base.add_file_to_container(
                container, file_path, file_data,
                make_dirs=True,
                raise_on_error=False))
        container.push.assert_called_with(file_path, file_data, make_dirs=True)

        # Raises:
        with self.assertRaises(ValueError):
            container = mock.MagicMock()
            container.push.side_effect = ValueError
            legend_operator_base.add_file_to_container(
                container, file_path, file_data,
                make_dirs=True,
                raise_on_error=True)

    @mock.patch("base64.b64decode")
    @mock.patch("OpenSSL.crypto.load_certificate")
    def test_parse_base64_certificate_formats(self, _load_cert_mock, _b64decode_mock):
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
        _load_cert_mock.assert_has_calls([
            mock.call(crypto.FILETYPE_PEM, test_decoded),
            mock.call(crypto.FILETYPE_ASN1, test_decoded)])

    @mock.patch("OpenSSL.crypto.dump_certificate")
    def test_create_jks_truststore_with_certificates(self, _mock_dump_cert):
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
        store = legend_operator_base.create_jks_truststore_with_certificates({
            cert_name: dummy_cert})
        _mock_dump_cert.assert_called_once_with(
            crypto.FILETYPE_ASN1, dummy_cert)
        self.assertIsInstance(store, jks.KeyStore)
        self.assertEqual(store.store_type, legend_operator_base.TRUSTSTORE_TYPE_JKS)
        self.assertTrue(store.certs)
        self.assertTrue(cert_name in store.certs)
        self.assertEqual(store.certs[cert_name].cert, cert_data)

    @mock.patch("subprocess.check_output")
    def test_get_ip_address(self, _mock_check_output):
        ip = b"random IP"
        _mock_check_output.return_value = ip
        res = legend_operator_base.get_ip_address()
        _mock_check_output.assert_called_once_with(["unit-get", "private-address"])
        self.assertEqual(res, ip.decode())


class TestBaseFinosLegendCharm(legend_operator_testing.BaseFinosLegendCharmTestCase):
    """Baseline testcase putting the base testcase through its motions with a
    `legend_operator_testing.BaseFinosLegendTestCharm`.
    """

    @classmethod
    def _set_up_harness(cls):
        rel_data = {
            rel: {"interface": "%s-interfaces" % rel}
            for rel in legend_operator_testing.BaseFinosLegendTestCharm._get_required_relations()}
        charm_meta = {
            "name": "legend-base-test",
            "requires": {"ingress": {"interface": "ingress"}},
            "provides": rel_data,
            "containers": {
                legend_operator_testing.BaseFinosLegendTestCharm._get_workload_container_name(): {
                    "resource": "image"}},
            "resources": {"image": {"type": "oci-image"}}}
        harness = ops_testing.Harness(
            legend_operator_testing.BaseFinosLegendTestCharm,
            meta=yaml.dump(charm_meta))
        return harness

    def test_workload_container(self):
        self._test_workload_container()

    def test_get_logging_level_from_config(self):
        self._test_get_logging_level_from_config()

    def test_setup_jks_truststore(self):
        self._test_setup_jks_truststore()

    @mock.patch("ops.testing._TestingPebbleClient.stop_services")
    def test_get_relation(self, _stop_legend_services):
        self._test_get_relation()

    @mock.patch("ops.testing._TestingPebbleClient.start_services")
    @mock.patch("ops.testing._TestingPebbleClient.stop_services")
    def test_relations_waiting(self, _container_stop, _container_start):
        self._test_relations_waiting(_container_stop, _container_start)


class BaseFinosLegendCoreServiceTestCharm(
        legend_operator_base.BaseFinosLegendCoreServiceCharm,
        legend_operator_testing.BaseFinosLegendTestCharm):

    REDIRECT_URIS = ["http://service.legend:443/callback"]

    # NOTE(aznashwan): DB relation is always checked first:
    RELATIONS = ['legend_db', 'legend_gitlab']
    RELATIONS_DATA = {
        "legend_db": {"database": "relation test data"},
        "legend_gitlab": {"gitlab": "relation test data"}}

    @classmethod
    def _get_legend_gitlab_relation_name(cls):
        return "legend_gitlab"

    @classmethod
    def _get_legend_db_relation_name(cls):
        return "legend_db"

    def _get_legend_gitlab_redirect_uris(self):
        return self.REDIRECT_URIS

    def _get_core_legend_service_configs(self, legend_db_credentials, legend_gitlab_credentials):
        return self.SERVICE_CONFIG_FILES


class TestBaseFinosCoreServiceLegendCharm(
        legend_operator_testing.TestBaseFinosCoreServiceLegendCharm):
    """Simulates a core service run through the above `BaseFinosLegendCoreServiceTestCharm`."""

    @classmethod
    def _set_up_harness(cls):
        rel_data = {
            rel: {"interface": "%s-interfaces" % rel}
            for rel in BaseFinosLegendCoreServiceTestCharm._get_required_relations()}
        charm_meta = {
            "name": "legend-base-test",
            "requires": {"ingress": {"interface": "ingress"}},
            "provides": rel_data,
            "containers": {
                BaseFinosLegendCoreServiceTestCharm._get_workload_container_name(): {
                    "resource": "image"}},
            "resources": {"image": {"type": "oci-image"}}}
        harness = ops_testing.Harness(
            BaseFinosLegendCoreServiceTestCharm,
            meta=yaml.dump(charm_meta))
        return harness

    @mock.patch("ops.testing._TestingPebbleClient.start_services")
    @mock.patch("ops.testing._TestingPebbleClient.stop_services")
    def test_relations_waiting(self, _container_stop, _container_start):
        self._test_relations_waiting(_container_stop, _container_start)
