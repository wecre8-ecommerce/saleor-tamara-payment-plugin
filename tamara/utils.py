import logging

import graphene
import requests

logger = logging.getLogger(__name__)


def get_base_api_url(config):
    sandbox = config.connection_params.get("sandbox", False)
    return "https://api-sandbox.tamara.co" if sandbox else "https://api.tamara.co"


def call_tamara_post(data, config, endpoint="/"):
    api_token = config.connection_params.get("api_token")
    return requests.post(
        url=get_base_api_url(config=config) + endpoint,
        headers={
            "Authorization": "Bearer " + api_token,
            "Content-Type": "application/json",
        },
        json=data,
    ).json()


def call_tamara_get(data, config, endpoint="/"):
    api_token = config.connection_params.get("api_token")
    return requests.get(
        url=get_base_api_url(config=config) + endpoint,
        headers={
            "Authorization": "Bearer " + api_token,
            "Content-Type": "application/json",
        },
        json=data,
    ).json()


def check_payment_supported(payment_information):
    """Check that a given payment is supported."""
    if payment_information.amount < 100:
        return (
            "Invalid amount, Amount must be greater "
            "than or equal to 100 to pay with Tamara."
        )


def _success_response(
    kind: str,
    payment_response: dict,
    token=None,
    amount=None,
    currency=None,
    customer_id=None,
    raw_response=None,
    action_required=True,
    action_required_data: dict = None,
):
    from saleor.payment.interface import GatewayResponse, PaymentMethodInfo

    return GatewayResponse(
        kind=kind,
        error=None,
        amount=amount,
        is_success=True,
        currency=currency,
        transaction_id=token,
        customer_id=customer_id,
        action_required=action_required,
        action_required_data=action_required_data,
        raw_response=raw_response or payment_response,
        payment_method_info=PaymentMethodInfo(type="card"),
    )


def _error_response(
    error,
    kind: str,
    payment_info,
    raw_response: dict = None,
    action_required: bool = False,
):
    from saleor.payment.interface import GatewayResponse, PaymentMethodInfo

    return GatewayResponse(
        kind=kind,
        error=error,
        is_success=False,
        raw_response=raw_response,
        amount=payment_info.amount,
        currency=payment_info.currency,
        action_required=action_required,
        customer_id=payment_info.customer_id,
        transaction_id=str(payment_info.token),
        payment_method_info=PaymentMethodInfo(type="card"),
    )


def get_order_items_data(lines, manager, discounts, checkout_info):
    from saleor.checkout.calculations import checkout_line_total

    return [
        {
            "sku": line.variant.sku,
            "quantity": line.line.quantity,
            "name": line.line.variant.product.name,
            "reference_id": str(line.line.checkout_id),
            "total_amount": {
                "currency": line.line.checkout.currency,
                "amount": float(
                    checkout_line_total(
                        lines=lines,
                        manager=manager,
                        discounts=discounts,
                        checkout_line_info=line,
                        checkout_info=checkout_info,
                    ).gross.amount
                ),
            },
            "type": line.line.variant.product.product_type.name,
        }
        for line in lines
    ]


def get_tamara_address_payload(address):
    from saleor.order.notifications import get_address_payload

    address = get_address_payload(address)
    address["line1"] = address["street_address_1"]
    address["line2"] = address["street_address_2"]
    address["region"] = address["city_area"]
    address["country_code"] = address["country"]
    address["phone_number"] = address["phone"]
    return address


def generate_checkout_session_request_data(config, amount, payment_information):
    from saleor.checkout.calculations import checkout_shipping_price, checkout_total
    from saleor.checkout.fetch import fetch_checkout_info, fetch_checkout_lines
    from saleor.discount.utils import fetch_active_discounts
    from saleor.payment.models import Payment
    from saleor.plugins.manager import get_plugins_manager

    manager = get_plugins_manager()
    payment = Payment.objects.get(pk=payment_information.payment_id, is_active=True)
    is_mobile = payment.get_value_from_metadata("is_mobile", False)
    payment_type = payment.get_value_from_metadata(
        "payment_type", "PAY_BY_LATER"
    ).upper()

    cancel_url = payment.get_value_from_metadata("cancel_url")
    success_url = payment.get_value_from_metadata("success_url")
    failure_url = payment.get_value_from_metadata("failure_url")
    notification_url = config.connection_params.get("notification_url")

    discounts = fetch_active_discounts()
    lines = fetch_checkout_lines(checkout=payment.checkout)
    checkout_info = fetch_checkout_info(
        checkout=payment.checkout, lines=lines, discounts=discounts, manager=manager
    )
    checkout_total = checkout_total(
        lines=lines,
        manager=manager,
        checkout_info=checkout_info,
        address=checkout_info.billing_address,
    )
    shipping_price = checkout_shipping_price(
        lines=lines,
        manager=manager,
        checkout_info=checkout_info,
        address=checkout_info.shipping_address,
    )

    request_data = {
        "is_mobile": is_mobile,
        "payment_type": payment_type,
        "order_reference_id": str(checkout_info.checkout.token),
        "total_amount": {"amount": amount, "currency": payment_information.currency,},
        "tax_amount": {
            "currency": checkout_total.tax.currency,
            "amount": float(checkout_total.tax.amount),
        },
        "shipping_amount": {
            "currency": shipping_price.gross.currency,
            "amount": float(shipping_price.gross.amount),
        },
        "merchant_url": {
            "cancel": cancel_url,
            "success": success_url,
            "failure": failure_url,
            "notification": notification_url,
        },
        "country_code": checkout_info.get_country(),
        "description": "Order #{}".format(str(checkout_info.checkout.token)),
        "items": get_order_items_data(lines[0], manager, discounts, checkout_info),
        "consumer": {
            "last_name": checkout_info.user.last_name,
            "email": checkout_info.get_customer_email(),
            "first_name": checkout_info.shipping_address.first_name,
            "phone_number": checkout_info.shipping_address.phone.as_e164,
        },
        "locale": "en-US" if payment.checkout.language_code == "en" else "ar-SA",
        "billing_address": get_tamara_address_payload(checkout_info.billing_address),
        "shipping_address": get_tamara_address_payload(checkout_info.shipping_address),
    }
    return request_data


def get_payment_customer_id(payment_information):
    from saleor.account.models import User

    pk = User.objects.filter(email=payment_information.customer_email).first().id
    return graphene.Node.to_global_id("User", pk) if pk else ""
