# Copyright 2021 Canonical
# See LICENSE file for licensing details.

import base64
import logging
import traceback

from OpenSSL import crypto
import jks

from finos_legend_operator import constants


logger = logging.getLogger(__name__)


def add_file_to_container(
        container, file_path, file_data, make_dirs=True,
        raise_on_error=True):
    """Adds a file with the given data under the given filepath via Pebble API.

    Args:
        container: `ops.model.Container` instance to add the file into.
        file_path: string absolute path to the file to write.
        file_data: string data to write into the file.
        make_dirs: whether or not to create parent directories if needed.
        raise_on_error: whether or not the function should re-raise errors.

    Returns:
        True if the file was successfully added, False (or raises) otherwise.

    Raises:
        ops.prebble.ProtocolError: if the container connection fails.
        ops.pebble.PathError: if the path is invalid and/or make_dirs=False
    """
    logger.debug(
        "Adding file '%s' in container '%s'", file_path, container.name)
    try:
        container.push(file_path, file_data, make_dirs=make_dirs)
    except Exception:
        logger.error(
            "Exception occurred while adding file '%s' in container '%s':\n%s",
            file_path, container.name, traceback.format_exc())
        if raise_on_error:
            raise
        return False
    logger.debug(
        "Successfully added file '%s' in container '%s'",
        file_path, container.name)
    return True


def parse_base64_certificate(b64_cert):
    """Parses the provided base64-encoded X509 certificate and returns the
    afferent `OpenSSL.crypto.X509` instance for it.

    Args:
        b64_cert: str or bytes representation of the base64-encoded cert.

    Returns:
        `OpenSSL.crypto.X509` instance.

    Raises:
        ValueError: on input/base64 formatting issues.
        OpenSSL.crypto.Error: on any OpenSSL-related operation failing.
    """
    if not isinstance(b64_cert, (str, bytes)):
        raise ValueError(
            "Argument must be either str or bytes. Got: %s" % b64_cert)
    
    raw_cert = base64.b64decode(b64_cert)
    formats = [crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1]
    format_errors = {}
    certificate = None
    for fmt in formats:
        try:
            certificate = crypto.load_certificate(fmt, raw_cert)
            break
        except Exception:
            format_errors[fmt] = traceback.format_exc()
    if not certificate:
        raise ValueError(
            "Failed to load certificate. Per-format errors were: %s",
            format_errors)
    return certificate


def create_jks_truststore_with_certificates(truststore_name, certificates):
    """Creates a `jks.truststore` with the provided certificates.

    Args:
        truststore_name: string name of the truststore.
        certificates: dict of the form:
        {
            "cert1": <OpenSSL.crypto.X509>,
            "cert2": <OpenSSL.crypto.X509>
        }


    Returns:
        `jks.KeyStore` with the provided certificates added as trusted.

    Raises:
        ValueError: if provided anything but a list of `OpenSSL.crypto.X509`s.
    """
    if not isinstance(certificates, dict) and not all([
            isinstance(c, crypto.X509) for c in certificates.values()]):
        raise ValueError(
            "Requires a dictionary of strings to `OpenSSL.crypto.X509` "
            "instances. Got: %r", certificates)

    cert_entries = []
    for cert_name, cert in certificates.items():
        dumped_cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
        entry = jks.TrustedCertEntry.new(cert_name, dumped_cert)
        cert_entries.append(entry)
    return jks.KeyStore.new(
        constants.TRUSTSTORE_TYPE_JKS, cert_entries)
