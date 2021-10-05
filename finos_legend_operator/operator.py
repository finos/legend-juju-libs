# Copyright 2021 Canonical
# See LICENSE file for licensing details.

"""Module defining the Base FINOS Legend Charmed operator class."""

import abc
import logging

from ops import charm
from ops import framework

from finos_legend_operator import constants

from charms.finos_legend_db_k8s.v0 import legend_database
from charms.finos_legend_gitlab_integrator_k8s.v0 import legend_gitlab
from charms.nginx_ingress_integrator.v0 import ingress


logger = logging.getLogger(__name__)


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
        container_ready_attr = "%s_pebble_ready" % (
            self._workload_container_name)
        self.framework.observe(
            getattr(self.on, container_ready_attr),
            self._on_workload_container_pebble_ready)

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

    @abc.abstractmethod
    def _get_service_configs(
            self, legend_db_credentials, legend_gitlab_credentials):
        """Returns a list of config files required for the Legend service.

        Args:
            legend_db_credentials: dict of the form:
            {
                "uri": "<replica set URI (with user/pass, no DB name)>",
                "username": "<username>",
                "password": "<password>",
                "database": "<database name>"
            }

            legend_gitlab_credentials: dict of the form:
            {
                "client_id": "<client_id>",
                "client_secret": "<client_secret>"
                "openid_discovery_url": "<URL>",
                "gitlab_host": "<GitLab hostname or IP>",
                "gitlab_port": <port>,
                "gitlab_scheme": "<http/https>",
                "gitlab_host_cert_b64": "<base64 DER certificate>"
            }

        Returns:
            A `model.BlockedStatus` on error, or a dict of the following form:
            {
                "/path/to/config-file-1.txt": "<contents of config file>",
                "/legend.json": '{"example": "config"}'
            }
        """
        raise NotImplementedError("No Legend service config implemented.")

    @property
    def _workload_container_name(self):
        """Returns the string name of the main workload container."""
        return self._get_workload_container_name()

    def _get_logging_level_from_config(self, option_name) -> str:
        """Fetches the config option with the given name and checks to
        ensure that it is a valid `java.utils.logging` log level.

        Args:
            option_name: string name of the config option.

        Returns:
            String logging level to be passed to the Legend service.

        Returns None if an option is invalid.
        """
        value = self.model.config[option_name]
        if value not in constants.VALID_APPLICATION_LOG_LEVEL_SETTINGS:
            logger.warning(
                "Invalid Java logging level value provided for option "
                "'%s': '%s'. Valid Java logging levels are: %s. The charm "
                "shall block until a proper value is set.",
                option_name, value,
                constants.VALID_APPLICATION_LOG_LEVEL_SETTINGS)
            return None
        return value

    @property
    def _workload_container(self):
        """Returns the `model.Container` pertaining to this unit.

        Returns:
            A `model.Container` instance or None if container isn't up yet.
        """
        container = self.unit.get_container(self._workload_container_name)
        if container.can_connect():
            return container
        return None
