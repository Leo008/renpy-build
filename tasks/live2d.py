from renpybuild.context import Context
from renpybuild.task import task, annotator


@annotator
def annotate(c: Context):
    c.include("{{ install }}/cubism/Core/include")
    c.env("CUBISM", "{{ install }}/cubism")


@task(platforms="all")
def build(c: Context):
    """安装已校验的 Cubism 5-r.4.1 编译头文件；Core 运行兼容性另行验收。"""
    c.clean()

    c.var("cubism_zip", "CubismSdkForNative-5-r.4.1.zip")
    c.var("cubism_dir", "CubismSdkForNative-5-r.4.1")

    c.var("live2d", c.path("{{ root }}/live2d"))

    if not c.path("{{ tars }}/{{ cubism_zip }}").exists():
        raise FileNotFoundError("[RenPyCI] 缺少 Cubism 5-r.4.1 完整 SDK 编译头文件")

    print("[RenPyCI] 使用 Cubism 5-r.4.1 头文件；本任务不链接或打包其 Core 二进制")

    c.run("unzip -q {{ tars }}/{{ cubism_zip }}")

    c.rmtree("{{ install }}/cubism")
    c.run("mv {{cubism_dir}} {{ install }}/cubism")
