# Copyright 2021 Canonical
# See LICENSE file for licensing details.

"""Module defining the Base FINOS Legend Charmed operator class."""

import abc
import logging

from ops import charm
from ops import framework


APPLICATION_CONNECTOR_TYPE_HTTP = "http"
APPLICATION_CONNECTOR_TYPE_HTTPS = "https"
GITLAB_REQUIRED_SCOPES = ["openid", "profile", "api"]

logger = logging.getLogger(__name__)

from charms.finos_legend_db_k8s.v0 import legend_database
from charms.finos_legend_gitlab_integrator_k8s.v0 import legend_gitlab
from charms.nginx_ingress_integrator.v0 import ingress


class BaseFinosLegendCharm(charm.CharmBase, metaclass=abc.ABCMeta):
    """Base class for all FINOS Legend Charmed Operators."""

    _stored = framework.StoredState()

    def __init__(self, *args):
        super().__init__(*args)

        self._set_stored_defaults()

        # Get relation names:
        legend_db_relation_name = self._get_legend_db_relation_name()
        legend_gitlab_relation_name = self._get_gitlab_relation_name()

        # Related charm library consumers:
        self._legend_db_consumer = legend_database.LegendDatabaseConsumer(
            self, relation_name=legend_db_relation_name)
        self._legend_gitlab_consumer = legend_gitlab.LegendGitlabConsumer(
            self, relation_name=legend_gitlab_relation_name)
        self.ingress = ingress.IngressRequires(
            self, {
                "service-hostname": self.app.name,
                "service-name": self.app.name,
                "service-port": self._get_application_connector_port()})

        # Standard charm lifecycle events:
        self.framework.observe(
            self.on.config_changed, self._on_config_changed)
        self.framework.observe(
            self.on.sdlc_pebble_ready, self._on_sdlc_pebble_ready)

        # DB relation lifecycle events:
        self.framework.observe(
            self.on[legend_db_relation_name].relation_joined,
            self._on_db_relation_joined)
        self.framework.observe(
            self.on[legend_db_relation_name].relation_changed,
            self._on_db_relation_changed)

        # GitLab integrator relation lifecycle events:
        self.framework.observe(
            self.on[legend_gitlab_relation_name].relation_joined,
            self._on_legend_gitlab_relation_joined)
        self.framework.observe(
            self.on[legend_gitlab_relation_name].relation_changed,
            self._on_legend_gitlab_relation_changed)

    def _set_stored_defaults(self):
        pass

    @classmethod
    @abc.abstractmethod
    def _get_gitlab_relation_name(cls):
        """Returns the string name of the GitLab Integrator relation."""
        raise NotImplementedError("No GitLab relation name defined.")

    @classmethod
    @abc.abstractmethod
    def _get_legend_db_relation_name(cls):
        """Returns the string name of the Legend DB Manager relation."""
        raise NotImplementedError("No Legend DB relation name defined.")

    @classmethod
    @abc.abstractmethod
    def _get_application_connector_port(cls):
        """Returns the integer port number the application is listening on."""
        raise NotImplementedError("No application connector port defined.")

    @classmethod
    @abc.abstractmethod
    def _get_workload_container_name(cls):
        """Returns the string name of the main workload container."""
        raise NotImplementedError("No workload container name defined.")

    @abc.abstractmethod
    def _get_workload_pebble_layer(self):
        """Returns a dict representing the Pebble layer for the workload."""
        raise NotImplementedError("No workload Pebble layer defined.")
