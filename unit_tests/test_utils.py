# Copyright 2021 Canonical
# See LICENSE file for licensing details.

"""Module defining base testing utilities for the library/child charms."""

import unittest
from unittest import mock

import jks
from OpenSSL import crypto

from finos_legend_operator import constants
from finos_legend_operator import utils


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

    def test_add_file_to_container(self):
        file_path = "/test/path"
        file_data = "Some file data."

        # Positive test:
        container = mock.MagicMock()
        self.assertTrue(
            utils.add_file_to_container(
                container, file_path, file_data, make_dirs=True,
                raise_on_error=False))
        container.push.assert_called_with(file_path, file_data, make_dirs=True)

        # Check make_dir passed:
        container = mock.MagicMock()
        make_dirs = "random value"
        self.assertTrue(
            utils.add_file_to_container(
                container, file_path, file_data, make_dirs=make_dirs,
                raise_on_error=False))
        container.push.assert_called_with(file_path, file_data, make_dirs=make_dirs)

        # No re-raise:
        container = mock.MagicMock()
        container.push.side_effect = ValueError
        self.assertFalse(
            utils.add_file_to_container(
                container, file_path, file_data,
                make_dirs=True,
                raise_on_error=False))
        container.push.assert_called_with(file_path, file_data, make_dirs=True)

        # Raises:
        with self.assertRaises(ValueError):
            container = mock.MagicMock()
            container.push.side_effect = ValueError
            utils.add_file_to_container(
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
        cert = utils.parse_base64_certificate(test_cert)
        self.assertEqual(cert, test_cert)
        _b64decode_mock.assert_called_with(test_cert)
        _load_cert_mock.assert_has_calls([
            mock.call(crypto.FILETYPE_PEM, test_decoded),
            mock.call(crypto.FILETYPE_ASN1, test_decoded)])

    @mock.patch("OpenSSL.crypto.dump_certificate")
    def test_create_jks_truststore_with_certificates(self, _mock_dump_cert):
        # Bad inputs:
        with self.assertRaises(ValueError):
            utils.create_jks_truststore_with_certificates(13)
        with self.assertRaises(ValueError):
            utils.create_jks_truststore_with_certificates({"cert": 13})

        # No inputs:
        cert_name = "cert"
        cert_data = "anything"
        _mock_dump_cert.return_value = cert_data
        dummy_cert = generate_dummy_cert()
        store = utils.create_jks_truststore_with_certificates({cert_name: dummy_cert})
        _mock_dump_cert.assert_called_once_with(
            crypto.FILETYPE_ASN1, dummy_cert)
        self.assertIsInstance(store, jks.KeyStore)
        self.assertEqual(store.store_type, constants.TRUSTSTORE_TYPE_JKS)
        self.assertTrue(store.certs)
        self.assertTrue(cert_name in store.certs)
        self.assertEqual(store.certs[cert_name].cert, cert_data)

    @mock.patch("subprocess.check_output")
    def test_get_ip_address(self, _mock_check_output):
        ip = b"random IP"
        _mock_check_output.return_value = ip
        res = utils.get_ip_address()
        _mock_check_output.assert_called_once_with(["unit-get", "private-address"])
        self.assertEqual(res, ip.decode())
