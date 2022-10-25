import json
import logging
from datetime import datetime
from decimal import Decimal

from django.http import HttpRequest, HttpResponse, HttpResponseForbidden
from saleor.payment import ChargeStatus

from tamara.utils import (
    _error_response,
    _success_response,
    call_tamara_get,
    call_tamara_post,
    check_payment_supported,
    generate_checkout_session_request_data,
    get_payment_customer_id,
)

logger = logging.getLogger(__name__)


def create_tamara_checkout_session(payment_information, config):
    """Create a Tamara session using the Tamara client."""
    from saleor.payment import TransactionKind

    error = check_payment_supported(payment_information=payment_information)

    if not error:
        session_data = generate_checkout_session_request_data(
            config=config,
            payment_information=payment_information,
            amount=float(payment_information.amount),
        )
        tamara_data = call_tamara_post(
            data=session_data, config=config, endpoint="/checkout"
        )
        if tamara_data.get("errors"):
            response = _error_response(
                action_required=True,
                raw_response=tamara_data,
                kind=TransactionKind.AUTH,
                error=tamara_data.get("message"),
                payment_info=payment_information,
            )
        else:
            response = _success_response(
                action_required=True,
                kind=TransactionKind.AUTH,
                payment_response=tamara_data,
                token=tamara_data.get("order_id"),
                amount=payment_information.amount,
                currency=payment_information.currency,
                customer_id=get_payment_customer_id(payment_information),
                action_required_data={
                    "checkout_url": tamara_data.get("checkout_url"),
                },
            )
            from saleor.payment.models import Payment

            payment_instance = Payment.objects.get(pk=payment_information.payment_id)
            payment_instance.token = payment_instance.psp_reference = tamara_data.get(
                "order_id"
            )
            payment_instance.save(update_fields=["token", "psp_reference"])
    else:
        response = _error_response(
            error=error,
            raw_response=None,
            action_required=True,
            kind=TransactionKind.AUTH,
            payment_info=payment_information,
        )
    return response


def capture_payment(payment_information, config):
    """Capture an authorized payment using the Checkout client.

    But it is first check if the given payment instance is supported
    by the gateway.
    If an error from Checkout occurs, we flag the transaction as failed and return
    a short user-friendly description of the error after logging the error to stderr.
    """
    from saleor.payment.models import Payment, TransactionKind

    payment = Payment.objects.get(pk=payment_information.payment_id)
    data = {
        "order_id": payment.token,
        "total_amount": {
            "currency": payment_information.currency,
            "amount": float(payment_information.amount),
        },
        "shipping_info": {
            "shipping_company": "OTO",
            "shipped_at": str(datetime.now()),
        },
    }
    tamara_data = call_tamara_post(
        data=data, config=config, endpoint="/payments/capture"
    )

    if tamara_data.get("errors") and not tamara_data.get("capture_id"):
        response = _error_response(
            action_required=True,
            raw_response=tamara_data,
            kind=TransactionKind.CAPTURE,
            error=tamara_data.get("message"),
            payment_info=payment_information,
        )
    else:
        response = _success_response(
            action_required=True,
            payment_response=tamara_data,
            kind=TransactionKind.CAPTURE,
            token=payment_information.token,
            amount=payment_information.amount,
            currency=payment_information.currency,
            customer_id=get_payment_customer_id(payment_information),
        )
        payment.store_value_in_metadata({"capture_id": tamara_data.get("capture_id", "")})
        payment.save(update_fields=["metadata"])
    return response


def refund_payment(payment_information, config):
    from saleor.payment import TransactionKind
    from saleor.payment.models import Payment

    payment = Payment.objects.get(pk=payment_information.payment_id)
    data = {
        "order_id": payment.token,
        "refunds": [
            {
                "total_amount": {
                    "currency": payment_information.currency,
                    "amount": float(payment_information.amount),
                },
                "capture_id": payment.get_value_from_metadata("capture_id"),
            }
        ],
    }
    tamara_data = call_tamara_post(
        data=data, config=config, endpoint="/payments/refund"
    )

    if tamara_data.get("errors"):
        response = _error_response(
            action_required=False,
            raw_response=tamara_data,
            kind=TransactionKind.REFUND,
            error=tamara_data.get("message"),
            payment_info=payment_information,
        )
    else:
        response = _success_response(
            action_required=False,
            payment_response=tamara_data,
            kind=TransactionKind.REFUND,
            token=payment_information.token,
            amount=payment_information.amount,
            currency=payment_information.currency,
            customer_id=get_payment_customer_id(payment_information),
        )
    return response


def confirm(payment_information, config):
    from saleor.payment import TransactionKind
    from saleor.payment.interface import GatewayResponse
    from saleor.payment.models import Payment

    tamara_order_id = Payment.objects.get(pk=payment_information.payment_id).token
    tamara_data = call_tamara_get(
        data=None, config=config, endpoint="/orders/{}".format(tamara_order_id)
    )

    response = GatewayResponse(
        error=None,
        is_success=False,
        raw_response=None,
        transaction_id="",
        action_required=True,
        kind=TransactionKind.CONFIRM,
        amount=payment_information.amount,
        currency=payment_information.currency,
    )

    if tamara_data.get("errors") or tamara_data.get("status") != "fully_captured":
        response = _error_response(
            action_required=True,
            raw_response=tamara_data,
            kind=TransactionKind.CONFIRM,
            error=tamara_data.get("message"),
            payment_info=payment_information,
        )
    else:
        if tamara_data.get("status") == "fully_captured":
            response = _success_response(
                token=tamara_order_id,
                action_required=False,
                payment_response=tamara_data,
                kind=TransactionKind.CONFIRM,
                amount=payment_information.amount,
                currency=payment_information.currency,
                customer_id=get_payment_customer_id(payment_information),
            )
    return response


def cancel_tamara_payment(payment, config):
    data = {
        "total_amount": {
            "currency": payment.currency,
            "amount": float(payment.captured_amount),
        },
    }
    tamara_data = call_tamara_post(
        data=data, config=config, endpoint="/orders/{}/cancel".format(payment.token)
    )

    if not tamara_data.get("errors"):
        payment.order.store_value_in_metadata(
            {"tamara_cancel_id": tamara_data.get("cancel_id", "")}
        )
        payment.order.save(update_fields=["metadata"])

        payment.store_value_in_metadata(
            {"tamara_cancel_id": tamara_data.get("cancel_id", "")}
        )
        payment.save(update_fields=["metadata"])


def process_tamara_payment(payment_information, config):
    return create_tamara_checkout_session(
        payment_information=payment_information, config=config
    )


def confirm_tamara_payment(payment_information, config):
    return confirm(payment_information=payment_information, config=config)


def capture_tamara_payment(payment_information, config):
    return capture_payment(payment_information=payment_information, config=config)


def refund_tamara_payment(payment_information, config):
    return refund_payment(payment_information=payment_information, config=config)


def verify_webhook(request: HttpRequest, config):
    # JWT decode with the HS256 algorithm
    if request.headers.get("Tamara-Signature") != config.connection_params.get(
        "signature"
    ):
        return HttpResponseForbidden()
    return True


def handle_tamara_webhook(request: HttpRequest, config, gateway: str):
    data_from_tamara = json.loads(request.body.decode("utf-8").replace("'", '"'))

    # Verify the webhook signature.
    if verify_webhook(request=request, config=config) is True:
        if data_from_tamara.get("event_type") == "order_captured":
            payment_data = data_from_tamara.get("data", {})
            if payment_data:
                from saleor.payment.models import Payment

                order_id = data_from_tamara.get("order_id", None)
                payment = Payment.objects.filter(token=order_id, gateway=gateway).last()

                if payment is not None:
                    if payment.checkout:
                        from saleor.payment.gateways.adyen.webhooks import create_order
                        from saleor.plugins.manager import get_plugins_manager

                        # Create the order into the database
                        order = create_order(
                            payment=payment,
                            checkout=payment.checkout,
                            manager=get_plugins_manager(),
                        )

                        if not order:
                            logger.info(
                                "Order not created for payment %s using Tamara webhook",
                                payment.id,
                            )
                            return HttpResponse(
                                "Order not created using the Tamara webhook"
                            )

                        # Mark the payment as paid
                        amount = payment.captured_amount = Decimal(
                            payment_data.get("captured_amount").get("amount")
                        )
                        payment.charge_status = (
                            ChargeStatus.FULLY_CHARGED
                            if amount >= payment.total
                            else ChargeStatus.PARTIALLY_CHARGED
                        )
                        payment.save(
                            update_fields=[
                                "modified",
                                "charge_status",
                                "captured_amount",
                            ]
                        )

                        # Remove the unneeded payments from the database.
                        for p in order.payments.exclude(id=payment.id):
                            p.transactions.all().delete()
                            p.delete()

                        logger.info(
                            msg=f"Order #{order.id} created",
                            extra={"order_id": order.id},
                        )
                        return HttpResponse("OK", status=200)
                return HttpResponse("Payment not found", status=200)
        return HttpResponse("OK", status=200)


def handle_tamara_authorization(request: HttpRequest, config, gateway: str):
    data_from_tamara = json.loads(request.body.decode("utf-8").replace("'", '"'))

    # Verify the webhook signature.
    if data_from_tamara.get("order_status") == "approved":
        from saleor.payment.models import Payment

        order_id = data_from_tamara.get("order_id", None)
        payment = Payment.objects.filter(token=order_id, gateway=gateway).last()

        if payment is not None:
            if payment.checkout:

                response = call_tamara_post(
                    config=config,
                    data={"orderId": order_id},
                    endpoint="/orders/{}/authorise".format(order_id),
                )
                if response.get("errors"):
                    logger.info(
                        "Order not created for payment %s using Tamara webhook",
                        payment.id,
                    )
                    return HttpResponse("Order not created using the Tamara webhook")
                else:
                    from saleor.payment.gateway import capture
                    from saleor.plugins.manager import get_plugins_manager

                    manager = get_plugins_manager()

                    transaction = capture(
                        payment=payment,
                        manager=manager,
                        amount=payment.total,
                        channel_slug=payment.checkout.channel.slug,
                    )

                    from saleor.payment.utils import gateway_postprocess

                    gateway_postprocess(transaction, payment)

                    payment.refresh_from_db()
                    if payment.charge_status == ChargeStatus.FULLY_CHARGED:
                        payment.to_confirm = True
                        payment.save(update_fields=["to_confirm"])

                    return HttpResponse("Payment captured", status=200)
        return HttpResponse("Payment not found", status=200)
