from renpybuild.context import Context
from renpybuild.task import task


@task(kind="python")
def clean(c: Context):
    c.clean()



@task(kind="host-python", platforms="all", pythons="3", always=True)
def gen_static3(c: Context):
    """生成静态模块及 C API 头文件，缺失时立即终止源码构建。"""

    c.chdir("{{ renpy }}")
    c.env("RENPY_DEPS_INSTALL", "/usr::/usr/lib/x86_64-linux-gnu/")
    c.env("RENPY_STATIC", "1")
    c.env("RENPY_REGENERATE_CYTHON", "1")
    c.run("{{ hostpython }} setup.py generate")
    header = c.path("{{ renpy }}/tmp/gen3-static/renpy.pygame.surface_api.h")
    if not header.is_file():
        raise RuntimeError(f"[RenPyCI] 静态 Cython API 头文件未生成：{header}")
    print(f"[RenPyCI] 静态 Cython API 头文件已验证：{header.name}")


@task(kind="python", platforms="all", always=True)
def build(c: Context):
    """编译静态模块，使用与 Cython 输出一致的生成目录查找 API 头文件。"""

    if c.platform == "web" and c.python == "2":
        return

    c.env("CFLAGS", """{{ CFLAGS }} "-I{{ renpy }}/src" "-I{{renpy}}/tmp/gen3-static" """)
    c.env("CXXFLAGS", """{{ CXXFLAGS }} "-I{{ renpy }}/src" "-I{{renpy}}/tmp/gen3-static" """)
    print("[RenPyCI] librenpy 使用 tmp/gen3-static 中的静态 Cython API 头文件")

    gen = "gen3-static/"

    modules = [ ]
    sources = [ ]

    def read_setup(dn, suffix=""):

        with open(dn / ("Setup" + suffix)) as f:
            for l in f:
                l = l.partition("#")[0]
                l = l.strip()

                if not l:
                    continue

                parts = l.split()

                if parts[0] == "renpy.compat.dictviews" and c.python != "2":
                    continue

                modules.append(parts[0])

                for i in parts[1:]:
                    if "libhydrogen" not in i:
                        i = i.replace("gen/", gen)
                    sources.append(dn / i)

    read_setup(c.renpy / "src" )
    read_setup(c.root / "extensions")

    if c.platform == "android":
        read_setup(c.path("{{ pytmp }}/pyjnius"))

    if c.platform == "ios" or c.platform == "mac":
        read_setup(c.path("{{ install }}/pyobjus"))

    if c.platform == "windows" or c.platform == "mac" or c.platform == "linux":
        read_setup(c.renpy / "src", ".tfd")

    if c.platform == "web" and c.python == "3":
        read_setup(c.path("{{ install }}/emscripten_pyx"))

    read_setup(c.path("{{ source }}/brotli"))

    objects = [ ]

    with c.run_group() as g:

        for source in sources:

            name, _, ext = str(source.name).rpartition(".")

            object = name + ".o"
            objects.append(object)

            c.var("src", source)
            c.var("object", object)

            if ext == "c":
                g.run("{{ CC }} {{ CFLAGS }} -c {{ src }} -o {{ object }}")
            else:
                g.run("{{ CXX }} {{ CXXFLAGS }} -c {{ src }} -o {{ object }}")

        c.generate("{{ runtime }}/librenpy_inittab{{ c.python }}.c", "inittab.c", modules=modules)
        g.run("{{ CC }} {{ CFLAGS }} -c inittab.c -o inittab.o")
        objects.append("inittab.o")

    c.var("objects", " ".join(objects))

    c.unlink("librenpy.a")
    c.run("{{ AR }} r librenpy.a {{ objects }} inittab.o")
    c.run("{{ RANLIB }} librenpy.a")

    c.copy("librenpy.a", "{{ install }}/lib/librenpy.a")
