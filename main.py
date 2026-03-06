import ida_hexrays
import ida_lines
import ida_diskio
import ida_kernwin
import idaapi
from pathlib import Path


INDENT_CHAR = "┊"
ENABLE_GUIDES = True

Liner: "Line"


class Line():
	def __init__(self, indent: int, char: str):
		self.indent = indent
		self.char = char

	@property
	def GAP(self):
		return " " * self.indent

	@property
	def LINE(self):
		return ida_lines.COLSTR(self.char + " " * (self.indent - 1), ida_lines.SCOLOR_AUTOCMT)


def get_usr_indent() -> int:
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
			except:
				pass

	return 2


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


def init_liner():
	global Liner
	indent = get_usr_indent()
	Liner = Line(indent, INDENT_CHAR)
	ida_hexrays.change_hexrays_config(f"BLOCK_INDENT = {indent}")


def is_label_ln(line: str) -> bool:
	ln = ida_lines.tag_remove(line)
	return not ln.startswith(" ") and ln.endswith(":")


def is_empty_ln(line: str) -> bool:
	ln = ida_lines.tag_remove(line)
	return len(ln) == 0


def get_label_insert(line: str, indent: int) -> str:
	line_len = len(ida_lines.tag_remove(line))
	if line_len + Liner.indent - 1 >= indent * Liner.indent:
		return str()
	pad = Liner.indent - (line_len % Liner.indent)
	count = indent - 1 - (line_len // Liner.indent)
	return ida_lines.COLSTR(" " * pad + Liner.LINE * count, ida_lines.SCOLOR_AUTOCMT)


def draw_lines(cfunc: ida_hexrays.cfunc_t):
	lines = [line for line in cfunc.get_pseudocode()]
	lines_stripped = [ida_lines.tag_remove(line.line).strip() for line in lines]
	indents = count_indents(lines_stripped)

	for i, line in enumerate(lines):
		n = 1
		if is_label_ln(line.line):
			line.line += get_label_insert(line.line, indents[i])
			n = 0
		elif is_empty_ln(line.line):
			line.line += Liner.GAP * indents[i]

		line.line = line.line.replace(Liner.GAP, Liner.LINE, indents[i]).replace(Liner.LINE, Liner.GAP, n)


ACTION_NAME = "idaguides:toggle"

class ToggleGuidesHandler(ida_kernwin.action_handler_t):
	def __init__(self):
		ida_kernwin.action_handler_t.__init__(self)

	def activate(self, ctx):
		global ENABLE_GUIDES
		ENABLE_GUIDES = not ENABLE_GUIDES
		status = "Enabled" if ENABLE_GUIDES else "Disabled"
		print(f"[IDA Guides] {status}")
		
		widget = ida_kernwin.get_current_widget()
		if widget:
			vdui = ida_hexrays.get_widget_vdui(widget)
			if vdui:
				vdui.refresh_view(True)
		return 1

	def update(self, ctx):
		return ida_kernwin.AST_ENABLE_ALWAYS


class IDAGuides(ida_hexrays.Hexrays_Hooks):
	def __init__(self):
		super().__init__()

	def func_printed(self, cfunc: ida_hexrays.cfunc_t) -> int:
		if ENABLE_GUIDES:
			draw_lines(cfunc)
		return 0

	def populating_popup(self, widget, popup, vdui):
		ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME, None)
		return 0


class IDAGuides_Plugin(idaapi.plugin_t):
	wanted_name = "IDA Guides Toggle"
	wanted_hotkey = "Ctrl-Shift-J"
	flags = 0

	def init(self):
		if not idaapi.init_hexrays_plugin():
			return idaapi.PLUGIN_SKIP

		desc = ida_kernwin.action_desc_t(
			ACTION_NAME,
			"IDA Guides Toggle",
			ToggleGuidesHandler(),
			"",
			"Toggle HexRays indention",
			-1
		)
		ida_kernwin.register_action(desc)

		init_liner()
		self.hook = IDAGuides() # type: ignore
		self.hook.hook()
		return idaapi.PLUGIN_KEEP

	def run(self, arg):
		global ENABLE_GUIDES
		ENABLE_GUIDES = not ENABLE_GUIDES
		status = "Enabled" if ENABLE_GUIDES else "Disabled"
		print(f"[IDA Guides] {status}")
		
		widget = ida_kernwin.get_current_widget()
		if widget:
			vdui = ida_hexrays.get_widget_vdui(widget)
			if vdui:
				vdui.refresh_view(True)

	def term(self):
		ida_kernwin.unregister_action(ACTION_NAME)
		if hasattr(self, 'hook'):
			self.hook.unhook()


def PLUGIN_ENTRY():
	return IDAGuides_Plugin() # type: ignore
