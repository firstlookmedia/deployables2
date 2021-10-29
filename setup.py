import setuptools

setuptools.setup(
    name="deployables2",
    version="0.1.5",
    author="Micah Lee",
    author_email="micah.lee@firstlook.media",
    description="A basket of deploy scripts",
    packages=["deployables2"],
    entry_points={
        "console_scripts": [
            "deployables2 = deployables2:main",
        ],
    },
)
