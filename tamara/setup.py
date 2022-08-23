from setuptools import setup

setup(
    name="tamara",
    version="0.1.0",
    packages=["tamara"],
    package_dir={"tamara": "tamara"},
    description="Tamara payment plugin integration",
    entry_points={
        "saleor.plugins": ["tamara = tamara.plugin:TamaraGatewayPlugin"],
    },
)
