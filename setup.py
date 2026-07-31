from setuptools import find_packages, setup

setup(
    name="phishtriage",
    version="1.0.0",
    description="Supheli e-postalari otomatik triyaj eden SOC araci",
    packages=find_packages(exclude=["tests"]),
    python_requires=">=3.8",
    entry_points={"console_scripts": ["phishtriage=phishtriage.cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)
