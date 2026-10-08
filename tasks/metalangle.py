from renpybuild.context import Context
from renpybuild.task import task, annotator


@annotator
def annotate(c: Context):
    """分离 MetalANGLE 的编译和链接参数，兼容启用 -Werror 的 CMake 依赖。"""
    if c.platform == "ios":
        c.env("CFLAGS", "{{ CFLAGS }} -F {{install}} -DMETALANGLE")
        c.env("CXXFLAGS", "{{ CXXFLAGS }} -F {{install}} -DMETALANGLE")
        c.env("LDFLAGS", "{{ LDFLAGS }} -F {{install}} -framework MetalANGLE")

@task(kind="python", platforms="ios")
def install(c: Context):
    """安装目标平台的 MetalANGLE framework，并记录编译参数分离策略。"""
    print("[RenPyCI] MetalANGLE: -F/-DMETALANGLE 用于编译，-framework 仅用于链接")
    c.clean("{{ install }}/MetalANGLE.framework")

    if c.arch.startswith("sim-"):
        c.run("unzip -d {{ install }} {{ source }}/MetalANGLE.framework.ios.simulator.zip")
    else:
        c.run("unzip -d {{ install }} {{ source }}/MetalANGLE.framework.ios.zip")
