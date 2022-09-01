import logging

import requests
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponseNotFound
from django.utils.translation import gettext_lazy as _
from saleor.graphql.core.enums import PluginErrorCode
from saleor.order.models import Order
from saleor.payment.gateways.utils import (
    get_supported_currencies,
    require_active_plugin,
)
from saleor.payment.interface import GatewayConfig, GatewayResponse, PaymentData
from saleor.plugins.base_plugin import BasePlugin, ConfigurationTypeField
from saleor.plugins.models import PluginConfiguration

from tamara import (
    cancel_tamara_payment,
    capture_tamara_payment,
    confirm_tamara_payment,
    handle_tamara_authorization,
    handle_tamara_webhook,
    process_tamara_payment,
    refund_tamara_payment,
)
from tamara.utils import get_base_api_url

GATEWAY_NAME = str(_("Tamara"))

logger = logging.getLogger(__name__)


class TamaraGatewayPlugin(BasePlugin):
    PLUGIN_NAME = GATEWAY_NAME
    PLUGIN_ID = "payments.tamara"
    CONFIGURATION_PER_CHANNEL = False
    PLUGIN_DESCRIPTION = "Tamara payment integration plugin"

    DEFAULT_CONFIGURATION = [
        {"name": "signature", "value": ""},
        {"name": "api_token", "value": None},
        {"name": "use_sandbox", "value": True},
        {"name": "notification_url", "value": ""},
        {"name": "notification_token", "value": None},
        {"name": "supported_currencies", "value": "SAR"},
    ]

    CONFIG_STRUCTURE = {
        "api_token": {
            "type": ConfigurationTypeField.SECRET,
            "help_text": "Provide your API token",
            "label": "API Token",
        },
        "notification_token": {
            "type": ConfigurationTypeField.SECRET,
            "help_text": "Provide your Notification token",
            "label": "Notification Token",
        },
        "use_sandbox": {
            "type": ConfigurationTypeField.BOOLEAN,
            "help_text": "Sandbox variable used for testing environment.",
            "label": "Sandbox",
        },
        "supported_currencies": {
            "type": ConfigurationTypeField.STRING,
            "help_text": "Supported Currencies for Checkout",
            "label": "Supported Currencies",
        },
        "signature": {
            "type": ConfigurationTypeField.STRING,
            "help_text": "Tamara Signature",
            "label": "Tamara Signature",
        },
        "notification_url": {
            "type": ConfigurationTypeField.STRING,
            "help_text": "Tamara Notification URL",
            "label": "Tamara Notification URL",
        },
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        configuration = {item["name"]: item["value"] for item in self.configuration}
        self.config = GatewayConfig(
            auto_capture=True,
            gateway_name=GATEWAY_NAME,
            connection_params={
                "signature": configuration["signature"],
                "sandbox": configuration["use_sandbox"],
                "api_token": configuration["api_token"],
                "notification_url": configuration["notification_url"],
                "notification_token": configuration["notification_token"],
            },
            supported_currencies=configuration["supported_currencies"],
        )

    def _get_gateway_config(self):
        return self.config

    @classmethod
    def validate_plugin_configuration(cls, plugin_configuration: "PluginConfiguration"):
        """Validate if provided configuration is correct."""

        missing_fields = []
        configuration = plugin_configuration.configuration
        configuration = {item["name"]: item["value"] for item in configuration}
        if not configuration["api_token"]:
            missing_fields.append("api_token")
        if not configuration["notification_url"]:
            missing_fields.append("notification_url")

        if plugin_configuration.active and missing_fields:
            error_msg = (
                "To enable a plugin, you need to provide values for the "
                "following fields: "
            )
            raise ValidationError(
                {
                    f"{field}": ValidationError(
                        error_msg.format(field),
                        code=PluginErrorCode.PLUGIN_MISCONFIGURED.value,
                    )
                    for field in missing_fields
                },
            )

    @require_active_plugin
    def get_payment_config(self, previous_value):
        config = self._get_gateway_config()
        api_token = config.connection_params["api_token"]
        base_api_url = f"{get_base_api_url(config=config)}/checkout/payment-types"

        checkout = self.requestor.checkouts.filter(total_gross_amount__gt=0).last()
        if not checkout:
            return []
        response = requests.get(
            url=base_api_url,
            headers={"Authorization": f"Bearer {api_token}"},
            params={
                "currency": checkout.currency,
                "country": checkout.country.code,
                "order_value": checkout.total_gross_amount,
            },
        ).json()
        return [
            {
                "value": response,
                "field": "payment_types",
            }
        ]

    @require_active_plugin
    def get_supported_currencies(self, previous_value):
        return get_supported_currencies(self.config, self.PLUGIN_NAME)

    def token_is_required_as_payment_input(self, previous_value):
        return False

    @require_active_plugin
    def process_payment(
        self, payment_information: "PaymentData", previous_value
    ) -> "GatewayResponse":
        return process_tamara_payment(
            payment_information=payment_information, config=self._get_gateway_config()
        )

    @require_active_plugin
    def capture_payment(
        self, payment_information: "PaymentData", previous_value
    ) -> "GatewayResponse":
        return capture_tamara_payment(payment_information, self._get_gateway_config())

    @require_active_plugin
    def refund_payment(
        self, payment_information: "PaymentData", previous_value
    ) -> "GatewayResponse":
        return refund_tamara_payment(payment_information, self._get_gateway_config())

    @require_active_plugin
    def confirm_payment(
        self, payment_information: "PaymentData", previous_value
    ) -> "GatewayResponse":
        return confirm_tamara_payment(payment_information, self._get_gateway_config())

    @require_active_plugin
    def order_cancelled(self, order: "Order", previous_value):
        last_payment = order.get_last_payment()
        if last_payment.gateway == self.PLUGIN_ID:
            cancel_tamara_payment(last_payment, self._get_gateway_config())
        return previous_value

    def webhook(self, request: HttpRequest, path: str, *args, **kwargs):
        if path == "/subscribe/" and request.method == "POST":
            response = handle_tamara_webhook(
                request=request,
                gateway=self.PLUGIN_ID,
                config=self._get_gateway_config(),
            )
            logger.info(msg=f"Finish handling {self.PLUGIN_ID} webhook")
            return response
        elif path == "/authorize/" and request.method == "POST":
            response = handle_tamara_authorization(
                request=request,
                gateway=self.PLUGIN_ID,
                config=self._get_gateway_config(),
            )
            logger.info(msg=f"Finish handling {self.PLUGIN_ID} authorize notification")
            return response if response else HttpResponseNotFound("Not Found")

        return HttpResponseNotFound("This path is not valid!")
