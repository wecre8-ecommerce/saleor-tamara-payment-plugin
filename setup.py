from setuptools import setup

setup(
    name="checkout-payment",
    version="0.1.0",
    packages=["checkout_payment"],
    package_dir={"checkout_payment": "checkout_payment"},
    description="Checkout payment plugin",
    install_requires=["checkout-sdk==2.0b8"],
    entry_points={
        "saleor.plugins": ["checkout_payment = checkout_payment.plugin:CheckoutGatewayPlugin"],
    },
)
