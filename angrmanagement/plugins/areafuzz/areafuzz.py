from angrmanagement.plugins import BasePlugin
from angrmanagement.ui.toolbars.toolbar import ToolbarAction
from PySide2.QtWidgets import QFileDialog
from .dpatch import run_patcher

class AreafuzzPlugin(BasePlugin):
	def __init__(self, workspace):
		super().__init__(workspace)
		toolbar = ToolbarAction(None, 'Patch selected function', 'Patch selected function', self.patch_function)
		self.workspace._main_window._analysis_toolbar.add(toolbar)

	def handle_click_block(self, qblock, event):
		pass	

	def patch_function(self, *args, **kwargs):
		view = self.workspace._get_or_create_disassembly_view()
		current_func = view._current_function
		if current_func.am_none == False:
			project = self.workspace.instance.project
			patched_name, _ = QFileDialog.getSaveFileName(None, 'Save patched file', '{}.patched'.format(project.filename))
			print(patched_name)
			run_patcher(
				project.filename,
				patched_name,
				current_func.name,
				'function'
			)

