# Copyright 2021 Canonical
# See LICENSE file for licensing details.

"""Module defining constants shared amongst FINOS Legend Charmed operators."""

APPLICATION_CONNECTOR_TYPE_HTTP = "http"
APPLICATION_CONNECTOR_TYPE_HTTPS = "https"
GITLAB_REQUIRED_SCOPES = ["openid", "profile", "api"]

VALID_APPLICATION_LOG_LEVEL_SETTINGS = [
    "INFO", "WARN", "DEBUG", "TRACE", "OFF"]
