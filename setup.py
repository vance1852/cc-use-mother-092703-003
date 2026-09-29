"""本地安装入口。"""

from setuptools import find_packages, setup


setup(
    name="compute-fabric-operations",
    version="0.1.0",
    description="数据中心调度、实验室准入、芯片资质与核技术应用许可流转服务",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    package_dir={"": "src"},
    packages=find_packages("src"),
    python_requires=">=3.11",
)
