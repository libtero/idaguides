import ida_hexrays
import ida_lines
import ida_diskio
import ida_kernwin
import idaapi
import json
from pathlib import Path


class Config:
    INDENT_CHAR = "¦"
    ACTION_NAME = "hx:ToggleGuides"

    def __init__(self):
        self.path = Path(__file__).parent / "ida-plugin.json"
        self.config: dict
        self.enabled: bool
        self.load()

    def load(self):
        self.config = json.loads(self.path.read_text())
        self.enabled = self.config.get("ENABLED", True)

    def save(self):
        self.config["ENABLED"] = self.enabled
        self.path.write_text(json.dumps(self.config, indent=4))

    def get_label(self):
        return "Hide indent guides" if self.enabled else "Show indent guides"

    def toggle(self):
        self.enabled = not self.enabled

    @staticmethod
    def get_hexrays_indent() -> int:
        if pdir := ida_diskio.get_user_idadir():
            cfg = Path(pdir) / "cfg/hexrays.cfg"
            if cfg.exists():
                try:
                    if data := open(cfg, "r").read():
                        for ln in data.splitlines():
                            if ln.strip().startswith("BLOCK_INDENT"):
                                if tokens := ln.split("="):
                                    if len(tokens) == 2:
                                        return int(tokens[1].strip(), 10)
                except ValueError | OSError:
                    pass
        return 2


class IDAGuides_ActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, config: Config):
        ida_kernwin.action_handler_t.__init__(self)
        self.config = config

    def activate(self, ctx):
        self.config.toggle()
        label = self.config.get_label()
        ida_kernwin.update_action_label(self.config.ACTION_NAME, label)

        widget = ida_kernwin.get_current_widget()
        if widget:
            vdui = ida_hexrays.get_widget_vdui(widget)
            if vdui:
                vdui.refresh_view(True)

        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class IDAGuides(ida_hexrays.Hexrays_Hooks):
    def __init__(self, config: Config):
        super().__init__()
        self.indent = 0
        self.config = config

    def func_printed(self, cfunc: ida_hexrays.cfunc_t) -> int:
        if self.config.enabled:
            self.run(cfunc)
        return 0

    def populating_popup(self, widget, popup, vdui):
        ida_kernwin.attach_action_to_popup(widget, popup, self.config.ACTION_NAME, None)
        return 0

    @staticmethod
    def count_indents(lines: list[str]) -> list[int]:
        levels = [0 for _ in range(len(lines))]
        indent = 0
        singleshot = 0
        switchtrace = list()
        colontrace = False

        for i in range(len(lines) - 1):
            levels[i] = max(indent, 0) + singleshot
            singleshot = 0
            ln = lines[i]
            nextln = lines[i + 1]
            prevln = lines[i - 1]

            if colontrace and ln.endswith(";"):
                indent -= 1
                colontrace = False

            if not ln.endswith("..."):
                if ln.startswith(("if", "else", "do")):
                    if not nextln.startswith("{") and nextln.endswith(";"):
                        singleshot = 1
                    elif not len(nextln):
                        colontrace = True
                        indent += 1

                elif ln.startswith("for") and ln.endswith(")"):
                    if not nextln.startswith("{"):
                        singleshot = 1

                elif ln.startswith("switch") and not ln.endswith(";"):
                    switchtrace.append(indent)
                    indent += 2

                elif ln.startswith("{"):
                    if not prevln.startswith("switch") and not prevln.endswith(";"):
                        indent += 1

                elif ln.endswith(":") and prevln.startswith(("if", "else", "do", "for")):
                    if nextln.endswith(";"):
                        singleshot = 1
                    else:
                        colontrace = True
                        indent += 1

            if nextln.startswith("case") and nextln.endswith(":"):
                singleshot = -1
            if nextln.startswith("}"):
                if switchtrace and indent - 2 == switchtrace[-1]:
                    indent -= 2
                    switchtrace.pop()
                else:
                    indent -= 1

        return levels

    def get_label_insert(self, line: str, indent: int) -> str:
        line_len = len(ida_lines.tag_remove(line))
        if line_len + self.indent - 1 >= indent * self.indent:
            return str()
        pad = self.indent - (line_len % self.indent)
        count = indent - 1 - (line_len // self.indent)
        return ida_lines.COLSTR(" " * pad + self.LINE * count, ida_lines.SCOLOR_AUTOCMT)

    def draw_lines(self, lines, indents: list[int]):
        for i, line in enumerate(lines):
            n = 1
            if self.is_label_ln(line.line):
                line.line += self.get_label_insert(line.line, indents[i])
                n = 0
            elif self.is_empty_ln(line.line):
                line.line += self.GAP * indents[i]
            line.line = line.line.replace(self.GAP, self.LINE, indents[i]).replace(self.LINE, self.GAP, n)

    def run(self, cfunc: ida_hexrays.cfunc_t):
        lines = [line for line in cfunc.get_pseudocode()]
        self.indent = self.get_indent_setting(lines)
        lines_stripped = [ida_lines.tag_remove(line.line).strip() for line in lines]
        indents = self.count_indents(lines_stripped)
        self.draw_lines(lines, indents)

    def get_indent_setting(self, lines: list[str]) -> int:
        ret = False
        for ln in lines:
            lc = ln.line
            if ret:
                return len(lc) - len(lc.lstrip(" "))
            if ida_lines.tag_remove(lc) == "{":
                ret = True
        indent = self.config.get_hexrays_indent()
        ida_hexrays.change_hexrays_config(f"BLOCK_INDENT = {indent}")
        return indent

    @staticmethod
    def is_label_ln(line: str) -> bool:
        ln = ida_lines.tag_remove(line)
        return not ln.startswith(" ") and ln.endswith(":")

    @staticmethod
    def is_empty_ln(line: str) -> bool:
        ln = ida_lines.tag_remove(line)
        return len(ln) == 0

    @property
    def GAP(self):
        return " " * self.indent

    @property
    def LINE(self):
        return ida_lines.COLSTR(self.config.INDENT_CHAR + " " * (self.indent - 1), ida_lines.SCOLOR_AUTOCMT)


class IDAGuides_Plugin(idaapi.plugin_t):
    wanted_name = "IDA Guides"
    flags = idaapi.PLUGIN_HIDE

    def init(self):
        if not idaapi.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        self.config = Config()
        desc = ida_kernwin.action_desc_t(
            self.config.ACTION_NAME,
            self.config.get_label(),
            IDAGuides_ActionHandler(self.config),
            "",
            "",
            -1,
        )
        ida_kernwin.register_action(desc)
        self.hook = IDAGuides(self.config)
        self.hook.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        self.config.toggle()
        widget = ida_kernwin.get_current_widget()
        if widget:
            vdui = ida_hexrays.get_widget_vdui(widget)
            if vdui:
                vdui.refresh_view(True)

    def term(self):
        ida_kernwin.unregister_action(self.config.ACTION_NAME)
        if hasattr(self, "hook"):
            self.hook.unhook()
        self.config.save()


def PLUGIN_ENTRY():
    return IDAGuides_Plugin()
